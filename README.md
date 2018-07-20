# ktest

```
$ java K
Usage: java K <common option>* <command> <option>*

Common options:

 -n[=lib] uses native provider
 -d       turns on debug

java K [-n] [-d] q <user> <key_or_tab> [<impersonate>] <peer> [-t] [-s] [-d] [-m]

Generates an AP_REQ.
For example: java K q username password -m -t

 user          my username, '-' uses the one in ccache
 key_or_tab    password/keytab, '-' ccache, '--' default keytab
 impersonate   impersonates this guy, if provided
 peer          peer principal name
 -talk         talks to peer
 -spnego       uses SPNEGO, otherwise, krb5
 -mutual       requests mutual
 -deleg        requests cred deleg

java K [-n] [-d] p <user> <key_or_tab> [-t] [-s] [<backend> [-t] [-s] [-d] [-m]]

Accepts an AP_REQ and possibly creates another
For example: java K p service keytab -t backend -t

 user          my username, '-' uses ccache
 key_or_tab    my password or keytab, '-' means ccache
 -talk         talks with client
 -spnego       uses SPNEGO, otherwise, krb5
 backend       if exists, getDeleg and creates an AP-REQ to backend
 -talk         talks with backend
 -spnego       uses SPNEGO to backend, otherwise, krb5
 -mutual       requests mutual to backend
 -deleg        requests cred deleg to backend

java K [-n] [-d] w [user] [pass] [scheme] <url>*

Grab a URL
For example: java K w kerberos http://www.protected.com

 user          my username
 pass          my password
 scheme        Negotiate or Kerberos or NTLM etc
 url           URL

java K d name pass etype
java K d keytab

Decrypt a Kerberos EncryptedData.
The stdin includes EncryptedData in hex or raw

 pname         Principal Name
 pass          password
 <usage>       Key usage number

java K c <option>* <command>+

Choreograph several commands talking to each other
For example: java K c "K -n q - - server -d" "K p server keytab backend" -d 3000 "K p backend keytab"

 -c            always uses color output
 -p            always uses prefix output
 -j <java>     uses this executable
 -d <delay>    delay in milliseconds
 -s            Run with security manager
 -v            Display full data
 command       Arguments of a java command
```
