- [x] Fix hardcoded password with an environment variable

- [x] Fix the SampleNetworkClient.py methods getTemperatureFromPort/authenticate to wrap sendto() in a try/catch with a 1 minute timeout to prevent DoS

- [x] Add a 'return' after the LOGOUT command that prevents unauthenticated command execution

- [x] Fix session token unbounded list to contain a maxiumum of 32

- Hardcoded nonce, should be replaced with salt/hash... should be a new vulnerability I think
will not do because it was included in app.py...

- Remove SimpleClient from SampleNetworkServer.py ?


Investigate the entirety of the provided source code and find the most critical vulnerabilities, at most 10. After identifying the vulnerabilities, provide me with detailed explanations on which lines of code from the source code create or are affected by each vulnerability. Provide me with the code changes required to fix the vulnerabilities, and how I can verify that the source code fix is working. I want a positive and negative test for each vulnerability that I can run locally to determine whether or not the fix works. The verification method can also include a one-off proof of concept script, a packet capture between the client/server, an execution trace of the program, or a before/after screenshot of the vulnerability being exploited and remediated. For each vulnerability, explain what method of verification is required to ensure it is remediated. Look for all types of vulnerabilities, such as information disclosure, denial of service, leaked credentials, authentication or authorization bypasses, or any other type that would deem the product unfit to launch in a real-world environment where an infant's health is at risk or a hospital worker cannot identify an issue. The risk landscape for this product includes attackers that are assumed to have the same network access as the server. Where applicable, map the vulnerability to the affected product requirement. The product requirements are listed in 'Product Requirements.md'.