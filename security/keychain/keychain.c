#include <CoreFoundation/CFString.h>
#include <Security/SecKeychain.h>
#include <Security/SecKeychainItem.h>
#include <ruby.h>
#include <ruby/encoding.h>

#define id_prefix(x) static ID id_##x;
#define sym_prefix(x) static VALUE sym_##x;
#ifndef numberof
#define numberof(array) ((int)(sizeof(array) / sizeof((array)[0])))
#endif

#define FOREACH_OPTIONS(x) \
    x(service) \
    x(server) \
    x(domain) \
    x(account) \
    x(path) \
    x(port) \
    x(protocol) \
    x(auth)

#ifdef HAVE_RB_SCAN_ARGS_OPTIONAL_HASH
FOREACH_OPTIONS(id_prefix)
#else
FOREACH_OPTIONS(sym_prefix)
#endif

#define GetStringArg(v) \
    const char *v##_ptr = 0; \
    UInt32 v##_len = 0; \
    if (!NIL_P(v)) { \
	SafeStringValue(v); \
	v##_ptr = RSTRING_PTR(v); \
	v##_len = rb_long2int(RSTRING_LEN(v));	\
    }
#define CheckStringArg(v) \
    if (!NIL_P(v) && (v##_ptr != RSTRING_PTR(v) || (long)v##_len != RSTRING_LEN(v))) { \
	rb_raise(rb_eArgError, #v" has been changed"); \
    }
#define GetSig(v) \
    UInt32 v##_str = 0; \
    if (!NIL_P(v)) { \
	SafeStringValue(v); \
	if (RSTRING_LEN(v) != 4) \
	    rb_raise(rb_eArgError, #v" must be exactly 4 characters long"); \
	const char *ptr = RSTRING_PTR(v); \
	v##_str = (unsigned char)ptr[0] << 24 | \
	    (unsigned char)ptr[1] << 16 | \
	    (unsigned char)ptr[2] << 8 | \
	    (unsigned char)ptr[3]; \
    }
#define GetArg(v) v = rb_hash_lookup2(opt, sym_##v, Qnil)

NORETURN(static void raise_secerror(OSStatus err));

static void
raise_secerror(OSStatus err)
{
    CFStringRef str = SecCopyErrorMessageString(err, NULL);
    const char *ptr = CFStringGetCStringPtr(str, kCFStringEncodingUTF8);
    VALUE mesg = rb_enc_str_new(ptr, strlen(ptr), rb_utf8_encoding());
    CFRelease(str);
    rb_exc_raise(rb_exc_new3(rb_eSecurityError, mesg));
}

static VALUE
keychain_find_generic_password(CFTypeRef keychain, VALUE service, VALUE account)
{
    void *passwddata;
    UInt32 passwdlen;
    VALUE passwd;
    OSStatus err;

    GetStringArg(service);
    GetStringArg(account);
    CheckStringArg(service);
    CheckStringArg(account);
    err = SecKeychainFindGenericPassword(keychain, service_len, service_ptr,
					 account_len, account_ptr,
					 &passwdlen, &passwddata, 0);
    if (err != noErr) {
	raise_secerror(err);
    }
    passwd = rb_str_new(passwddata, passwdlen);
    SecKeychainItemFreeContent(NULL, passwddata);
    return passwd;
}

/*
 * call-seq:
 *
 *   Security::Keychain.find_generic_password(service = nil, account = nil)       -> string
 *   Security::Keychain.find_generic_password(service: service, account: account) -> string
 *   Security::Keychain.generic_password(service = nil, account = nil)            -> string
 *   Security::Keychain.generic_password(service: service, account: account)      -> string
 *
 * Finds generic password by +service+ and +account+.
 */

static VALUE
rb_keychain_find_generic_password(int argc, VALUE *argv, VALUE self)
{
    VALUE opt = Qnil;
#ifdef HAVE_RB_SCAN_ARGS_OPTIONAL_HASH
    VALUE args[2];
    rb_scan_args(argc, argv, "02:", args+0, args+1, &opt);
    if (!NIL_P(opt)) {
        ID kwds[numberof(args)];
        int i = 0;
        kwds[i++] = id_service;
        kwds[i++] = id_account;
        rb_get_kwargs(opt, kwds, 0, i, args);
        for (i = 0; i < numberof(args); ++i) {
            if (args[i] == Qundef) args[i] = Qnil;
        }
    }
    return keychain_find_generic_password(NULL, args[0], args[1]);
#else
    VALUE service = Qnil, account = Qnil;
    if (argc > 0 && TYPE(opt = argv[argc - 1]) == T_HASH) {
	--argc;
    }
    else {
	opt = Qnil;
    }
    rb_scan_args(argc, argv, "02", &service, &account);
    if (!NIL_P(opt)) {
#define GetArg(v) v = rb_hash_lookup2(opt, sym_##v, Qnil)
	switch (argc) {
	  case 0: GetArg(service);
	  case 1: GetArg(account);
	}
    }
    return keychain_find_generic_password(NULL, service, account);
#endif
}

static VALUE
keychain_find_internet_password(CFTypeRef keychain, VALUE server, VALUE domain,
				VALUE account, VALUE path, VALUE port,
				VALUE protocol, VALUE auth)
{
    int portno = 0;
    void *passwddata;
    UInt32 passwdlen;
    VALUE passwd;
    OSStatus err;

    GetStringArg(server);
    GetStringArg(domain);
    GetStringArg(account);
    GetStringArg(path);
    if (!NIL_P(port)) portno = NUM2UINT(port);
    GetSig(protocol);
    GetSig(auth);
    CheckStringArg(server);
    CheckStringArg(domain);
    CheckStringArg(account);
    CheckStringArg(path);
    err = SecKeychainFindInternetPassword(keychain, server_len, server_ptr,
					  domain_len, domain_ptr, account_len, account_ptr,
					  path_len, path_ptr, portno,
					  (SecProtocolType)protocol_str, (SecAuthenticationType)auth_str,
					  &passwdlen, &passwddata, 0);
    if (err != noErr) {
	raise_secerror(err);
    }
    passwd = rb_str_new(passwddata, passwdlen);
    SecKeychainItemFreeContent(NULL, passwddata);
    return passwd;
}

/*
 * call-seq:
 *
 *   Security::Keychain.find_internet_password(server = nil, domain = nil, account = nil,
 *                                             path = nil, port = nil, protocol = nil, auth = nil) -> string
 *   Security::Keychain.find_internet_password(server: server, domain: domain, account: account,
 *                                             path: path, port: port, protocol: protocol, auth: auth) -> string
 *   Security::Keychain.internet_password(server = nil, domain = nil, account = nil,
 *                                        path = nil, port = nil, protocol = nil, auth = nil) -> string
 *   Security::Keychain.internet_password(server: server, domain: domain, account: account,
 *                                        path: path, port: port, protocol: protocol, auth: auth) -> string
 *
 * Finds internet password by +server+, +domain+, +account+, +path+,
 * +port+, +protocol+, and +auth+.
 */

static VALUE
rb_keychain_find_internet_password(int argc, VALUE *argv, VALUE self)
{
    VALUE opt = Qnil;

#ifdef HAVE_RB_SCAN_ARGS_OPTIONAL_HASH
    VALUE args[7];
    rb_scan_args(argc, argv, "07:", args+0, args+1, args+2, args+3,
                 args+4, args+5, args+6, &opt);
    if (!NIL_P(opt)) {
        ID kwds[numberof(args)];
        int i = 0;
        kwds[i++] = id_server;
        kwds[i++] = id_domain;
        kwds[i++] = id_account;
        kwds[i++] = id_path;
        kwds[i++] = id_port;
        kwds[i++] = id_protocol;
        kwds[i++] = id_auth;
        rb_get_kwargs(opt, kwds, 0, i, args);
        for (i = 0; i < numberof(args); ++i) {
            if (args[i] == Qundef) args[i] = Qnil;
        }
    }
    return keychain_find_internet_password(NULL, args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
#else
    VALUE server = Qnil, domain = Qnil, account = Qnil, path = Qnil;
    VALUE port = Qnil, protocol = Qnil, auth = Qnil;
    if (argc > 0 && TYPE(opt = argv[argc - 1]) == T_HASH) {
	--argc;
    }
    else {
	opt = Qnil;
    }
    rb_scan_args(argc, argv, "07", &server, &domain, &account, &path,
		 &port, &protocol, &auth);
    if (!NIL_P(opt)) {
	switch (argc) {
	  case 0: GetArg(server);
	  case 1: GetArg(domain);
	  case 2: GetArg(account);
	  case 3: GetArg(path);
	  case 4: GetArg(port);
	  case 5: GetArg(protocol);
	  case 6: GetArg(auth);
	}
    }
    return keychain_find_internet_password(NULL, server, domain, account, path, port, protocol, auth);
#endif
}

#ifdef HAVE_RB_SCAN_ARGS_OPTIONAL_HASH
#define make_sym(x) id_##x = rb_intern_const(#x);
#else
#define make_sym(x) sym_##x = ID2SYM(rb_intern(#x));
#endif

void
Init_keychain(void)
{
#undef rb_intern

    VALUE mSecurity = rb_define_module("Security");
    VALUE cKeychain = rb_define_class_under(mSecurity, "Keychain", rb_cObject);
    VALUE sKeychain = rb_singleton_class(cKeychain);
    rb_define_singleton_method(cKeychain, "find_generic_password", rb_keychain_find_generic_password, -1);
    rb_alias(sKeychain, rb_intern("generic_password"), rb_intern("find_generic_password"));
    rb_define_singleton_method(cKeychain, "find_internet_password", rb_keychain_find_internet_password, -1);
    rb_alias(sKeychain, rb_intern("internet_password"), rb_intern("find_internet_password"));
    FOREACH_OPTIONS(make_sym);
}
