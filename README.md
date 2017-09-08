# UnlimitID
[![Build Status](https://travis-ci.org/moullos/UnlimitID.svg?branch=master)](https://travis-ci.org/moullos/UnlimitID)
[![Coverage Status](https://coveralls.io/repos/github/moullos/UnlimitID/badge.svg?branch=master)](https://coveralls.io/github/moullos/UnlimitID?branch=master)
## Privacy-Preserving Federated Identity Management using Algebraic MACs

UnlimitID is a method for enhancing the privacy of commodity OAuth and applications such as OpenID Connect, using anonymous attribute-based credentials based on algebrai Message Authentication Codes (aMACs). OAuth is one of
the most widely used protocols on the Web, but it exposes each of the requests of a user for data by each relying party (RP) to the identity provider (IdP). Our approach allows for the creation of multiple persistent and unlinkable pseudo-
identities and requires no change in the deployed code of relying parties, only in identity providers and the client.

Full version of the paper published at WPES 2016 is available at http://www.cs.ucl.ac.uk/staff/M.Isaakidis/p/UnlimitID_WPES16.pdf


### Features
This repository includes 2 flask applications. UnlimitID/IdP is build upon [flask-oauthlib](https://flask-oauthlib.readthedocs.io/en/latest/) and provides all the typical OAuth2 endpoints along with two additional endpoints providing the necessary anonymous credentials and exposing the IdP's public parameters. UnlimitID/User provides all the out-of-band functionality preluding an UnlimitID flow. A demo version of the IdP can be found [here](https://unlimitid.online).

As both packages use [petlib](http://petlib.readthedocs.io/en/latest/) install the necessary libraries before attemping to run UnlimitID.

### Running the identity provider
**The easiest way to run the identity provider is through docker:**
1. Get the latest container
  ```
  $ docker pull unlimitid/idp:latest
  ```
2. Run it!
  ```
  $ docker run -p 80:80 -d unlimitid/idp:latest
  ```
  
**If you prefer to build the container on your own:**
1. Clone the repository
  ```
  $ git clone https://github.com/moullos/UnlimitID.git
  ```
2. Change directory
  ```
  $ cd UnlimitID
  ```
3. Build the container
  ```
  $ docker build -t your_tag_here . 
  ```
  
**If you don't want to use docker:**
1. Clone the repository
  ```  
  $ git clone https://github.com/moullos/UnlimitID.git
  ```
2. Change directory
  ```
  $ cd UnlimitID
  ```
3. Create a virtual env
  ```
  $ virtualenv env
  ```
  and activate it
  ```
  $ source env/bin/activate
  ```
4. Install the package 
  ```
  $ pip install .
  ```
5. Use the run_IdP.py
  ```
  $ python run_IdP.py
  ```

### Running the user
**In order for the user to run, an IdP must also be running in order for the user to obtain up-to-date parameters**
1. Clone the repository
  ```  
  $ git clone https://github.com/moullos/UnlimitID.git
  ```
2. Change directory
  ```
  $ cd UnlimitID
  ```
3. Create a virtual env
  ```
  $ virtualenv env
  ```
  and activate it
  ```
  $ source env/bin/activate
  ```
4. Install the package 
  ```
  $ pip install .
  ```
5. Use the run_user.py
  ```
  $ python run_user.py
  ```
Note: If you are running more than 1 components of the system locally, make sure that their cookies are isolated.

### Running the tests
**Just install and run tox after installing the package**
1. Install tox
  ```
  $ pip install tox
  ```
2. Run it!
  ```
  $ tox
  ```
