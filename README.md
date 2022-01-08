Mumba 
======
The multi-os p2p application platform based on Chromium
------

What is it?
------

* A full application platform that exposes the web api (and others) to native applications (not wasm based). 
  Think of it as a mix of a userspace OS + mobile application platform + a browser

* A multiprocess "userspace kernel" that takes care of running and managing applications
  forming a network of applications.

* Each application have at least a daemon process which serve gRPC api's and 
  answer for route requests from the UI clients via IPC or RPC
  The daemon process also manage the application launches which are full-blown
  web-based UI applications (in their own processes).

* The web api's are exposed directly to the native application, which is much more powerfull than
  the current Javascript ones given the UI application have direct access to the web frame api
  with the same power as the C++ 'renderer' process in Chrome.

* Multiples native applications SDK's are feasible. The Swift one is ready.

* Applications are distributed over torrent DHT, with permanent addresses without the need
  of third-parties for application and data distribution. You can create apps and share them
  right away from your computer.

* Applications will run as if they were native, with executable "frontends" which are shim rpc clients 
  which communicate with the mumba's mothership(host process) over RPC and without users even noticing 
  that theres a whole platform managing yours and others applications

* With a central manager process a lot of other things are possible, and thats why we call it 
  "application network", because each application can access public resources from other applications
  on the same host, as with RPC' api's application routes or the automation IPC api.

* With multiple RPC api's exposed in each node, distributed applications that combine the same api's 
  in several nodes are possible in a p2p fashion

* A storage layer which can serve a file, key-value and sql database api to the applications
  but that is also distributed over torrent, making all the storage a applications use
  (be it files or databases) available to other nodes in a p2p way.

  This storage layer is actually how applications are distributed over torrent, with their optional assets.
  But new files and databases can be created and shared over after the original storages are being
  seeded over the bit-torrent network

* its meant as a web.next platform. The next step combining the power of browsers and mobile platforms
   but with a peer-to-peer distribution process which put the power of creating, distributing, 
   sharing and downloading things back in the hand of everyone.

   The classic web have a technical design flaw that leads to the economical concentration of power we see today.
   In order to give back the power to ordinary people, giving them the means and independency to do what they dream
   theres a need for the distribution to have no middle-man, no hasless and no obligatory clouds. Clouds can be used
   of course but they get to be proxyfied by the application daemons and the users dont even need to know the details
   (if its going local, distributed or over the traditional cloud).

   The way this works, is about the "power of indirection". Its the same way how our brain represents the world
   we know "locally" through references to things, representations. The idea is that the application always talk to 
   its service(which is also programmed as the UI application) first which decides what to do according to its goals.

   If it needs to reach the network and how, the client application running in the same host doesnt need to know about it
   from the application point of view that is always accessing the same entry point, and the service process can
   have fallbacks once things on network dont work as intended. 

What you can do with it? What is it for?
------
  
  - A distributed twitter? 
  - So, do you mean Mastodon? 
  - No. Mastodon is federated. this "distributed whatever" can use its own desined gRPC's distributed on every user node
    communicating with them in a p2p fashion. 
    
    You can create a distributed database with a Raft logic for instanc. A CRDT editor or a multiplayer game.
    You can use RPC to leverage/bootstrap others low latency protocols like UDP, WebRTC or WebSockets if RPC is not a good fit.
    But having a common ground to form a network of peers with the same api can create wonderful applications 

Architecture
-----

RPC Apis
-----

  Every application have a service/daemon process which is always running like a service
  and which is responsible to answer for RPC and Route requests, among any other things
  a running daemon is suitable for.

Routes
-----

SDK
-----

How is this similar/different from
------

* Electron/Flutter

* Android/iOS  

* Documentation

Building
-----

  We use Chrome's gn for generating ninja build files and then ninja from there.
  Our gn's is a fork from the original which also allow us to build Swift sources
  to build the sdk or applications

Creating your applications
-----

Distributing your applications
-----
  
    
