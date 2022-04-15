// Container - abstract container interface to be implemented by the concrete implementations
//             (android, linux, chrome and kvm)

//            Container
//                |
// ContainerLXC ----- ContainerKVM
//      |       
//      |       
//      -------ContainerLinux
//                   |
// ContainerAndroid --- ContainerChrome

// Container interface should have api for both LXC and KVM
// where ContainerLXC is expected to have a OCI compatible interface