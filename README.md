# UnlimitID
## Privacy-Preserving Federated Identity Management using Algebraic MACs

UnlimitID is a method for enhancing the privacy of commodity OAuth and applications such as OpenID Connect, using anonymous attribute-based credentials based on algebrai Message Authentication Codes (aMACs). OAuth is one of
the most widely used protocols on the Web, but it exposes each of the requests of a user for data by each relying party (RP) to the identity provider (IdP). Our approach allows for the creation of multiple persistent and unlinkable pseudo-
identities and requires no change in the deployed code of relying parties, only in identity providers and the client.

Full version of the paper published at WPES 2016 is available at http://www.cs.ucl.ac.uk/staff/M.Isaakidis/p/UnlimitID_WPES16.pdf


### Features
czxcv * IdP implements an UnlimitID identity provider build upon flask-oauthlib 

 * User provides the necessary out-of-band functionality preluding a typical UnlimitID flow.



