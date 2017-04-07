# :rotating_light::fire: :key: Vault Incident Response :key: :fire: :rotating_light:
Preparing for, and responding to, an incident within Vault. This is not necessarily advice to help secure a Vault deployment, but instead, to help when it eventually fails.

## Preparing your Vault for a future incident and forensic review.
A quick checklist for Vault deployments to have proper "forensic readiness" to make an easier time for incident responders.

- [ ] Remember to enable the audit backend with `audit-enable`. This does not happen in the configuration file.
- [ ] Logs going to a centralized location, highly maintained for availability and searchable, and outside of any security blast radius as much as possible.
- [ ] Prepare to reverse hash values in any investigation.
- [ ] Tokens should have `display-name` to help assist log analysis.
- [ ] If you are instrumenting an application client that consumes a "response wrapped" token, and it sees a failure, this may be an exception to handle as a security event. Vault logs will not treat it as such.

### Notable insecure configurations
- [ ] Using `log_raw` will directly expose token values into your audit backend.
- [ ] Starting a server with `-dev` will degrade every single protection that Vault offers
- [ ] Using the `-id` parameter in any `vault token-create` as a method to create tokens may make tokens predictable or weak.

## These are the most likely incident response actions you'll take.

### Finding out where logs are flowing.
You'll first be verifying where logs are found.

`vault audit-list`

If this not available for some reason, a very, very small amount of what vault's behavior will will be available in the server's STDOUT, hopefully captured somehow.

### Preparing a wrapper script to assist with log hunting.
Vault logs are nearly unusable for DFIR without some important notes. Because token values are inherently high risk, Vault hashes them before writing them to logs. Vault also hashes just about everything else too.

You will not be able to start grepping or Splunking through logs as you may expect during an incident.

The [`/sys/audit-hash`](https://www.vaultproject.io/api/system/audit-hash.html) API is used to create these hashes. This is `hmac-sha56` with a salt, so you'll have to perform this hash on Vault itself or extract the salt and perform it elsewhere.

If the victim configuration has `hmac_accessor=false` in its audit backend, then the token accessor will be in plaintext. A token accessor references a token, which is more helpful for searching if you have one available to reference a compromised token.

### Understanding vault's log behavior.
Every request and response is logged, _if the token was valid_. So, hopefully, if you have logs, they should be thorough.

Invalid tokens are not logged to avoid DoS scenarios. If Vault cannot write to a log, it will not fulfill a request.

> If you have only one audit backend enabled, and it is blocking (network block, etc.), then Vault will be unresponsive. Vault will not complete any requests until the audit backend can write.

If Vault is being DoS'd, the audit backend may be a possible root cause. This vector would also imply a token is exposed to an adversary (because valid tokens are required to generate a log, and a disk I/O DoS would need one).

The `'.request.id'` field is also important in finding the corresponding `'.response'` to a request, as both are logged.

### Following up on a response wrapper breach.
Vault has a feature called "Response Wrapping", which creates a single use token that can access a single value. Think of it like a burner token as it's always been easier to explain, but this is not official Vault verbiage.

This command creates a secret value in the Vault `secret` backend that we will retrieve:

```
➜  ~ vault write secret/myname -value=rumplestiltskin          
Success! Data written to: secret/myname
```

This requests the secret, but instead of accessing it directly, it wraps the value it would respond with within a burner token, and returns the token.

```
➜  ~ vault read -wrap-ttl="1m" secret/myname          
Key                          	Value
---                          	-----
wrapping_token:              	d0f24a38-fd5b-97cd-d975-3ac1b3398d72
wrapping_token_ttl:          	1m0s
wrapping_token_creation_time:	2017-04-04 08:23:22.412065862 -0700 PDT
```

This unwraps the burner token to access the value.

```
➜  ~ vault unwrap d0f24a38-fd5b-97cd-d975-3ac1b3398d72
Key             	Value
---             	-----
refresh_interval	768h0m0s
-value          	rumplestiltskin
```

This tries to retrieve it a second time, but the token is burnt and doesn't exist anymore.

```
➜  ~ vault unwrap d0f24a38-fd5b-97cd-d975-3ac1b3398d72
Error making API request.

URL: PUT http://127.0.0.1:8200/v1/sys/wrapping/unwrap
Code: 400. Errors:

* wrapping token is not valid or does not exist
```

This error is not logged. A log would be expected behavior for a DFIR response, as it should indicate malicious replay behavior, but there is a reasonable explanation why it is not.

This Response Wrapping design pattern is meant to be useful when passing a secret through risky territory. If the token is unwrapped and burnt before arrival at its final destination, the intended recipient shouldn't be able to use the secret value. In practice, it's encouraged to use this sort of design pattern when injecting a token through a build environment that might be subject to operator snooping.

If the token is unwrapped before its final destination, this should be detectible as malicious behavior of some sort.

However, this does not create a log. As a DFIR responder looking at Vault logs (as of this date), you will not have evidence of a response wrapped breach in logs. This is because "burnt" tokens do not exist, and fall into the "invalid tokens do not log" policy to avoid DoS scenarios.

Thus, the only expected behavior would be a client error of some sort on the other end, as a consumer application of the secret would fail to do its job. For instance, a database client failing to authenticate itself because a password was not available to create the connection. I would not predict that applications acting as vault clients would include exception handling to surface this type of malicious behavior as an alert, but a client suddenly failing may be an indicator to a compromised response wrapper.

### Monitoring use of disabled tokens.
Similar to Response Wrapping, revoked tokens don't produce logs. You'll lose visibility into activity on a key you've disabled during incident response as an approach towards adversary containment. Thus, if that key were to be used by the adversary elsewhere on the network, you'll lose that additional insight that IR is incomplete and an adversary is off the network.

So, for example, if you were to disable an account on a server, you'd see failed SSH in authentication logs if the adversary was actively trying their previously compromised password. That failure might have forensic value during incident response. This is different with Vault logs, in that you wouldn't see the failure.

Consider applying a neutered `deny` policy to an abusive token to continue logging its access. You cannot modify the policies a token on the fly, but you can modify the policy itself or recreate the token again with `vault token-create` with the `id=` parameter of the same token, essentially creating a new token. Modifying the policy itself may destroy access for other tokens reliant on that policy. Recreating the token (with `id`) with a different policy will change its accessor.

### Understanding DoS risk from exposed token accessors.
Accessors are reference values for tokens. They allow you to operate on tokens in some ways without passing the actual token itself. Exposure of an accessor has a risk of the underlying token being revoked by access by `/auth/token/revoke*`. Accessors are documented as lower risk, as they have no ability to reveal secrets, but are valuable in terms of revocation.

If mass revocation by accessor is suspected and leakage is not immediately obvious, the `hmac_accessor=false` configuration in an audit backend will log accessors in plaintext, being a potential root cause for any unexpected, mass revocation.
