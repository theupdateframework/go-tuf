# Security audit of go-tuf

## The Update Framework

## Radoslav Dimitrov - 06/13/2023

go-tuf, a Go implementation of The Update Framework (TUF), plays a critical role in securely managing
software updates. Recently, a security assessment conducted by X41 D-Sec GmbH uncovered a few
security-related findings in go-tuf. The following blog post provides a concise overview of the
assessment's key findings and recommendations.

The assessment identified two vulnerabilities of medium and low severity in go-tuf, along with
four additional issues without immediate security implications. Even though there are no
high-severity issues, these vulnerabilities still pose risks in update integrity and local file
overwrite scenarios.

To address the vulnerabilities, it was recommended to implement measures such as linking versions
and making root metadata project-specific. Additionally, validating signatures for all files
processed by go-tuf will enhance protection against file manipulation during transit. Alongside
the identified vulnerabilities, the security assessment highlighted that the “keys” directory had
been assigned with world-readable permissions. Although this does not directly expose key files to
local attackers, it is considered a best practice to assign only the minimum necessary permissions.

Despite the discovery of only a few vulnerabilities and weaknesses, go-tuf demonstrates a high level
of maturity in terms of security. The security assessment conducted by X41 D-Sec GmbH underscores
the importance of continuously improving the project's security posture and implementing best practices.
Alongside maintaining the project, the maintainers of go-tuf are also working on a new code base
which is based on the positive redesign of python-tuf. This new code base is designed to be more
efficient, user-friendly, and easier to maintain. The ongoing efforts of the maintainers to improve
the project's design and simplicity will contribute to the overall health and long-term success
of go-tuf. By implementing the recommended measures, adhering to best practices, and leveraging
the advancements in the new code base, go-tuf will continue to provide a reliable and secure solution
for managing software updates.
