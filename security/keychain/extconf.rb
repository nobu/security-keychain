require 'mkmf'

if have_framework('CoreFoundation') and have_framework('Security')
  create_makefile('security/keychain')
end
