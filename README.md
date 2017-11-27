# KiteProxy

KiteProxy is a small set of guidances and tools that enables you **bypass DNS and SNI based web filtering** which is the filtering strategy used by Iranian Government to restrict access to websites such as **Youtube**, **Twitter**, **Facebook**, etc.

## How do they block websites?

### IP address ###

Blockers can block connections based on destination **IP address**. Smaller websites can be efficiently blocked this way, however there are huge downsides to this method. First of all, larger websites in general have multiple IPs (e.g. **Facebook** has more than 1,500 IPs. Secondly, companies might host multiple websites on the same IP address for example **Google.com** or **Gmail.com** are served on the same IP address that **Youtube.com** is served. In addition, IPs are rented monthly and they are cheap to rent (~1$/month) so website hosts can easily change their IP address; plus, blockers will not be notices when exactly a "bad-website" would let go of an IP and a "good-website" picks it up so that they can unfilter it. This makes management of "bad IPs" way too difficult for them.

### Payload ###

Blocker might pick connections based on **payload** (say for instance when your webpage contains a certain word like *freedom*). Currently a major part of websites use **secure end-to-end encryption** which completely disables blockers from knowing what is the payload of your target website which makes this approach outdated and . (the `https` you use before your website address ``https://youtube.com`` indicates you are using **http** protocol over a secure **TLS** connection)

### Domain name ###

Blockers intercept and disrupt **domain name resolution** to **IP address**. This is essentially what translates `youtube.com` to something like `216.58.201.110`. They technology you are using by default for name-resolution is plain-text old and insecure DNS which can be easily eavesdroppped and manipulated midway.

Good news is there are quite a few alternatives you can go for name resolution that are secure and non-interceptable (such as **dnscrypt**) which we will explain in next section.

### Network data-unit headers ###

There are several network layers involved in a connection and they each have their own headers. Well, even for a secure end-to-end connection there is still the risk that blockers might find a clue on these headers just the most you want to establish your **TLS** connection. One clue is **server_name_indicator (SNI)** extension on **SSL Client Hello** message which unfortunately exposes exactly which site you are trying to open.

Fortunately, this extension is not mandatory most of the time and it is used for mere load-balancing purposes therefore we can send a fake SNI instead of our actual target website's name. But there are still challenges in modifying SNI which makes overcoming this a bit harder.
