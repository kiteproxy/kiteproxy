# KiteProxy

KiteProxy is a small set of guidances and tools to enable you **bypass DNS and SNI based web filtering** which is the firewalling strategy that prevents you from accessing websites such as **Youtube**, **Twitter**, **Facebook**, etc. in Iran.

## How do they block websites?

#### IP address ####

Blockers can block connections based on destination **IP address**. Smaller websites can be efficiently blocked this way, however there are huge downsides to this method:
1. Larger websites in general have multiple IPs (e.g. **Facebook** has more than 1,500 IPs).
   - Sometimes companies host multiple websites on the same IP address for example **Google.com** is served on the same IP address that **Youtube.com** is served.
   - IP are rented monthly and they are cheap to rent (~1$/month) so it can easily be changed. In addition, blockers will not be notices exactly when a "bad-website" would let go of an IP and a "good-website" picks it up so that they can unfilter it. This makes management of "bad IPs" way too difficult for them.

#### Domain name ####

Blockers intercept and disrupt **domain name resolution** to **IP address**. This is essentially what translates `youtube.com` to something like `216.58.201.110`. They technology you are using by default for name-resolution is plain-text old and insecure DNS which can be easily eavesdroppped and manipulated midway.

#### Payload ####

Blocker might pick connections based on **payload** (say for instance when your webpage contains a certain word like *freedom*).
  - Currently a major part of websites use **secure end-to-end encryption** which disables blockers from knowing what is the payload of your target website. (the `https` you use before your website address ``https://youtube.com`` indicates you are using **http** protocol over a secure **TLS** connection)

#### Network data-unit headers ####

There are several network layers involved in a connection and they each have their own headers. Well, even for a secure end-to-end connection there is still the risk that blockers might find a clue on these headers just when you want to establish your **TLS** connection. One of these headers which they inspect now is **SNI**
