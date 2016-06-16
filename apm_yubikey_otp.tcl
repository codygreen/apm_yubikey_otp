### PROC FOR NONCE GENERATOR ###
proc randomNumberGenerator {length {chars "0123456789"}} {
  set range [expr {[string length $chars]-1}]
  set txt ""
  for {set i 0} {$i < $length} {incr i} {
    set pos [expr {int(rand()*$range)}]
    append txt [string range $chars $pos $pos]
  }
  return $txt
}

when ACCESS_POLICY_AGENT_EVENT {
  if { [ACCESS::policy agent_id] eq "otp_verify" } {
    # edit these variables
    set yubico_client_id "XXXXXX"
    set yubico_secret_key "XXXXXX" 
    # do not edit anything below this line
    set nonce [call randomNumberGenerator 25] 

    set yubico_server [RESOLV::lookup @8.8.8.8 -a "api2.yubico.com"]
    if {$yubico_server == ""} {
      log local0.error "could not resolve Yubico server"
      return
    }
    ACCESS::session data set "session.custom.otp_valid" 0
    ACCESS::session data set "session.custom.is_provisioned" 0

    set auth_user [ACCESS::session data get "session.logon.last.username"]
    # remove the last 32 characters to reveal the serial number
    set yubikey_serial [string trimleft [class lookup $auth_user yubikey_users] 0]
    # make sure a yubikey is provisioned for this user
    if { $yubikey_serial eq ""} {
      log local0.error "no yubikey assigned to $auth_user"
      return
    } else {
      ACCESS::session data set "session.custom.is_provisioned" 1

      # extract the Yubikey serial
      if { [string is integer -strict $yubikey_serial] } {
        # convert to modnex
        set yubikey_serial [split [format %012x $yubikey_serial] ""]
        set yubikey_modhex ""
        #array set modhex_alphabet { 0 c 1 b 2 d 3 e 4 f 5 g 6 h 7 i 8 j 9 k A l B n C r D t E u F v }
        array set modhex_alphabet {0 c 1 b 2 d 3 e 4 f 5 g 6 h 7 i 8 j 9 k a l b n c r d t e u f v}
        foreach index $yubikey_serial {
          append yubikey_modhex $modhex_alphabet($index)
        }
      }
    }

    # do we have an OTP? if so try and verify it
    set auth_otp [ACCESS::session data get session.logon.last.otp]
    if {$yubikey_modhex equals [string range $auth_otp 0 11]} {
      # build GET request to yubico
      set params "id=$yubico_client_id&nonce=$nonce&otp=$auth_otp"
      set signature [string map { "+" "%2B" } [b64encode [CRYPTO::sign -alg hmac-sha1 -key [b64decode $yubico_secret_key] $params]]]
      set yubico_get_request "GET /wsapi/2.0/verify?$params&h=$signature HTTP/1.1\r\n"
      append yubico_get_request "Host: api2.yubico.com\r\n"
      append yubico_get_request "Accept: */*\r\n\r\n"

      ## Create connection and send request
      set conn [connect -timeout 1000 -idle 30 $yubico_server:80]
      send -timeout 1000 -status send_status $conn $yubico_get_request
      ## Store Response from yubico
      set yubico_response [recv -timeout 1000 -status recv_info $conn]
      set otp_r [getfield [getfield $yubico_response "\r\n" 10] "=" 2]
      set nonce_r [getfield [getfield $yubico_response "\r\n" 11] "=" 2]
      set status [getfield [getfield $yubico_response "\r\n" 14] "=" 2]

      if {  ($auth_otp eq $otp_r) && ($nonce eq $nonce_r) } {
        ACCESS::session data set "session.custom.otp_valid" 1
      }
    } else {
      log local0.error "error with yubikey serial for $auth_user"
    }
  }
}
