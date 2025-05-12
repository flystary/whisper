## libconfig
    https://hyperrealm.github.io/libconfig/dist/libconfig-1.7.2.tar.gz
    tar -zxvf libconfig-1.7.2.tar.gz
    cd libconfig-1.7.2
    ./configure
    make -j8
    make check
    sudo make install
    sudo cp -d ./lib/libconfig* /usr/lib
    sudo ldconfig -v # 显示各种库位置

## log4cpp
    https://sourceforge.net/projects/log4cpp/files/latest/download

    cd log4cpp
 
    ./configure --with-pthreads
    
    make
    
    make check
    
    sudo make install
    
    sudo ldconfig

## libuv
    https://dist.libuv.org/dist/v1.31.0/libuv-v1.31.0.tar.gz

    $ sh autogen.sh
    $ ./configure
    $ make
    $ make check
    $ make install

## jsoncpp
    sudo apt-get install libjsoncpp-dev

    把 /usr/include/jsoncpp/json   json文件夹复制到/usr/include/


## iptables 
### fatal error: libiptc/libiptc.h: 没有那个文件或目录

    https://www.netfilter.org/projects/iptables/files/iptables-1.4.14.tar.bz2

    tar jxvf iptables-1.4.14.tar.bz2 

    $ sh autogen.sh
    $ ./configure
    $ make
    $ make check
    $ make install














