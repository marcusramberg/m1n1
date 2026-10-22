The managed macOS kernel rewrap workflow reads its IM4M from the private
GitHub Actions repository secret `D431_T8030_IM4M_B64`. The expected decoded
file SHA-256 is
`0389336c4d7091455d4c8edf52651915f8d8d2e57a5360e04007c51f14c9a35a`.

Keep the ticket out of the repository and workflow artifacts. Its manifest
contains a device ECID. To configure the secret, base64-encode the previously
audited `IM4M_0x8030` file and add the value in the repository's Actions
secrets. The workflow checks the decoded file hash before using it.
