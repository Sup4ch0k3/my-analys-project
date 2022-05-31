# Setup Remote Debug

1. Kill jetty process
2. Mount `mount -o remount,rw /`
3. Upload file `libjdwp.so` and `libdt_socket.so` to `/usr/lib/jvm/java-11-openjdk/lib`
4. Run command:
```
/lib/jvm/java-11-openjdk/bin/java -Xdebug -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 -Xmx384m -Xms12m -Xss256k -XX:MaxMetaspaceSize=100m -Dhybrid.enabled=false -Djna.tmpdir=/tmp/java -Djava.io.tmpdir=/tmp/java -Dsun.jnu.encoding=UTF-8 -Dfile.encoding=UTF-8 -Djava.awt.headless=true -Djetty.home=/usr/share/jetty -Djetty.base=/usr/share/jetty -jar /usr/share/jetty/start.jar --lib=/usr/share/webconsole/properties/
```
6. Forward port 5005 to localhost.
7. Debug
