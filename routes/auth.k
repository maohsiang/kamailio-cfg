route[AUTH] {
#!ifdef WITH_AUTH

#!ifdef WITH_IPAUTH
        if((!is_method("REGISTER")) && allow_source_address()) {
                # source IP allowed
                return;
        }
#!endif
        xlog("L_DEBUG", "[AUTH:$ci] $fd\n");
        if (is_method("REGISTER")) {
                # authenticate requests
                if (!auth_check("$fd", "subscriber", "1")) {
			xlog("L_DEBUG", "[AUTH] pass auth_check\n");
                        auth_challenge("$fd", "0");
                        exit;
                }
                # user authenticated - remove auth header
                if(!is_method("REGISTER|PUBLISH"))
                        consume_credentials();
        }
        # if caller is not local subscriber, then check if it calls
        # a local destination, otherwise deny, not an open relay here
        #if (from_uri!=myself && uri!=myself) {
        #        sl_send_reply("403","Not relaying - caller is not local");
        #        exit;
        #}

#!else

        # authentication not enabled - do not relay at all to foreign networks
        if(uri!=myself) {
                sl_send_reply("403","Not relaying - authentication is not enable");
                exit;
        }

#!endif
        return;
}

