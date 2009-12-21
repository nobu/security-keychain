require 'mkmf'

if have_header('CoreFoundation/CFString.h') and have_header('Security/SecKeychain.h')
  $LDFLAGS << ' -framework CoreFoundation -framework Security'
  $LIBS << ' -LCoreFoundation -LSecurity'
  create_makefile('security/keychain')
end
