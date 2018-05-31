## Shiro整合SSM框架和整合后的后台开发

### 0x01、shiro安全框架简介

​	1、Apache Shiro是一个强大且易用的**Java安全框架**,执行**身份验证**、**授权**、**密码学**和**会话管理**。使用Shiro的易于理解的API,您可以快速、轻松地获得任何应用程序,从最小的移动应用程序到最大的网络和企业应用程序。

​	2、Shiro 主要分为两个部分就是认证和授权，在个人感觉来看就是查询数据库做相应的判断而已，Shiro只是一个框架而已，其中的内容需要自己的去构建，前后是自己的，中间是Shiro帮我们去搭建和配置好的。

​	**Shiro的主要架构图：**

![image](https://images2015.cnblogs.com/blog/496517/201607/496517-20160728005413825-1139491997.png)

​	

​	3、shiro的一些对象和方法简单说明

​	**Subject**

​	Subject即主体，外部应用与subject进行交互，subject记录了当前操作用户，将用户的概念理解为当前操作的主体，可能是一个通过浏览器请求的用户，也可能是一个运行的程序。 Subject在shiro中是一个接口，接口中定义了很多认证授相关的方法，外部程序通过subject进行认证授，而subject是通过SecurityManager安全管理器进行认证授权

 	**SecurityManager** 

​	SecurityManager即安全管理器，对全部的subject进行安全管理，它是shiro的核心，负责对所有的subject进行安全管理。通过SecurityManager可以完成subject的认证、授权等，实质上SecurityManager是通过Authenticator进行认证，通过Authorizer进行授权，通过SessionManager进行会话管理等。

SecurityManager是一个接口，继承了Authenticator, Authorizer, SessionManager这三个接口。

​	 **Authenticator**

​	Authenticator即认证器，对用户身份进行认证，Authenticator是一个接口，shiro提供ModularRealmAuthenticator实现类，通过ModularRealmAuthenticator基本上可以满足大多数需求，也可以自定义认证器。

​	**Authorizer**

​	Authorizer即授权器，用户通过认证器认证通过，在访问功能时需要通过授权器判断用户是否有此功能的操作权限。

​	 **realm**

​	Realm即领域，相当于datasource数据源，securityManager进行安全认证需要通过Realm获取用户权限数据，比如：如果用户身份数据在数据库那么realm就需要从数据库获取用户身份信息。

注意：不要把realm理解成只是从数据源取数据，在realm中还有认证授权校验的相关的代码。

​	 **sessionManager**

​	sessionManager即会话管理，shiro框架定义了一套会话管理，它不依赖web容器的session，所以shiro可以使用在非web应用上，也可以将分布式应用的会话集中在一点管理，此特性可使它实现单点登录。

 	**SessionDAO**

​	SessionDAO即会话dao，是对session会话操作的一套接口，比如要将session存储到数据库，可以通过jdbc将会话存储到数据库。

​	**CacheManager**

​	CacheManager即缓存管理，将用户权限数据存储在缓存，这样可以提高性能。

​	**Cryptography**

​	Cryptography即密码管理，shiro提供了一套加密/解密的组件，方便开发。比如提供常用的散列、加/解密等功能。



### 0x02、shiro整合SSM步骤

​	1、添加jar包，可以通过在WebContent中的lib下添加相应的jar包（在image中有所需jar包的名词截图），或者通过Maven配置pom.xml。本项目未使用Maven。

​	2、配置web.xml，在web.xml中配置shiro过滤器，具体配置参考源码。

```
<!-- Shiro配置 -->
    <filter>
        <filter-name>shiroFilter</filter-name>
        <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
        <init-param>
            <param-name>targetFilterLifecycle</param-name>
            <param-value>true</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>shiroFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
```

​	3、添加shiro的核心配置文件applicationContext-shiro.xml，配置如下：

```
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns="http://www.springframework.org/schema/beans" xmlns:util="http://www.springframework.org/schema/util"
    xmlns:context="http://www.springframework.org/schema/context" xmlns:p="http://www.springframework.org/schema/p"
    xmlns:tx="http://www.springframework.org/schema/tx" xmlns:mvc="http://www.springframework.org/schema/mvc"
    xmlns:aop="http://www.springframework.org/schema/aop"
    xsi:schemaLocation="http://www.springframework.org/schema/beans
    http://www.springframework.org/schema/beans/spring-beans-4.0.xsd http://www.springframework.org/schema/tx
    http://www.springframework.org/schema/tx/spring-tx-4.0.xsd http://www.springframework.org/schema/context
    http://www.springframework.org/schema/context/spring-context-4.0.xsd http://www.springframework.org/schema/mvc
    http://www.springframework.org/schema/mvc/spring-mvc.xsd http://www.springframework.org/schema/aop
    http://www.springframework.org/schema/aop/spring-aop-4.0.xsd http://www.springframework.org/schema/util
    http://www.springframework.org/schema/util/spring-util.xsd">
     
    <!-- url过滤器 -->        
    <bean id="urlPathMatchingFilter" class="com.how2java.filter.URLPathMatchingFilter"/> 
     
    <!-- 配置shiro的过滤器工厂类，id- shiroFilter要和我们在web.xml中配置的过滤器一致 -->
    <bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean">
        <!-- 调用我们配置的权限管理器 -->
        <property name="securityManager" ref="securityManager" />
        <!-- 配置我们的登录请求地址 -->
        <property name="loginUrl" value="/login" />
        <!-- 如果您请求的资源不再您的权限范围，则跳转到/403请求地址 -->
        <property name="unauthorizedUrl" value="/unauthorized" />
        <!-- 退出 -->
        <property name="filters">
            <util:map>
                <entry key="logout" value-ref="logoutFilter" />
                <entry key="url" value-ref="urlPathMatchingFilter" />
            </util:map>
        </property>
        <!-- 权限配置 -->
        <property name="filterChainDefinitions">
            <value>
                <!-- anon表示此地址不需要任何权限即可访问 -->
                /login=anon
                /index=anon
                /static/**=anon
                <!-- 只对业务功能进行权限管理，权限配置本身不需要没有做权限要求，这样做是为了不让初学者混淆 -->
                /config/**=anon
                /doLogout=logout
                <!--所有的请求(除去配置的静态资源请求或请求地址为anon的请求)都要通过登录验证,如果未登录则跳到/login -->
                /** = url
            </value>
        </property>
    </bean>
    <!-- 退出过滤器 -->
    <bean id="logoutFilter" class="org.apache.shiro.web.filter.authc.LogoutFilter">
        <property name="redirectUrl" value="/index" />
    </bean>
 
    <!-- 会话ID生成器 -->
    <bean id="sessionIdGenerator"
        class="org.apache.shiro.session.mgt.eis.JavaUuidSessionIdGenerator" />
    <!-- 会话Cookie模板 关闭浏览器立即失效 -->
    <bean id="sessionIdCookie" class="org.apache.shiro.web.servlet.SimpleCookie">
        <constructor-arg value="sid" />
        <property name="httpOnly" value="true" />
        <property name="maxAge" value="-1" />
    </bean>
    <!-- 会话DAO -->
    <bean id="sessionDAO"
        class="org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO">
        <property name="sessionIdGenerator" ref="sessionIdGenerator" />
    </bean>
    <!-- 会话验证调度器，每30分钟执行一次验证 ，设定会话超时及保存 -->
    <bean name="sessionValidationScheduler"
        class="org.apache.shiro.session.mgt.ExecutorServiceSessionValidationScheduler">
        <property name="interval" value="1800000" />
        <property name="sessionManager" ref="sessionManager" />
    </bean>
    <!-- 会话管理器 -->
    <bean id="sessionManager"
        class="org.apache.shiro.web.session.mgt.DefaultWebSessionManager">
        <!-- 全局会话超时时间（单位毫秒），默认30分钟 -->
        <property name="globalSessionTimeout" value="1800000" />
        <property name="deleteInvalidSessions" value="true" />
        <property name="sessionValidationSchedulerEnabled" value="true" />
        <property name="sessionValidationScheduler" ref="sessionValidationScheduler" />
        <property name="sessionDAO" ref="sessionDAO" />
        <property name="sessionIdCookieEnabled" value="true" />
        <property name="sessionIdCookie" ref="sessionIdCookie" />
    </bean>
 
    <!-- 安全管理器 -->
    <bean id="securityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">
        <property name="realm" ref="databaseRealm" />
        <property name="sessionManager" ref="sessionManager" />
    </bean>
    <!-- 相当于调用SecurityUtils.setSecurityManager(securityManager) -->
    <bean
        class="org.springframework.beans.factory.config.MethodInvokingFactoryBean">
        <property name="staticMethod"
            value="org.apache.shiro.SecurityUtils.setSecurityManager" />
        <property name="arguments" ref="securityManager" />
    </bean>
 
    <!-- 密码匹配器 -->
    <bean id="credentialsMatcher" class="org.apache.shiro.authc.credential.HashedCredentialsMatcher">
        <property name="hashAlgorithmName" value="md5"/>
        <property name="hashIterations" value="2"/>
        <property name="storedCredentialsHexEncoded" value="true"/>
    </bean>
 
    <bean id="databaseRealm" class="com.how2java.realm.DatabaseRealm">
        <property name="credentialsMatcher" ref="credentialsMatcher"/>
    </bean>
     
    <!-- 保证实现了Shiro内部lifecycle函数的bean执行 -->
    <bean id="lifecycleBeanPostProcessor" class="org.apache.shiro.spring.LifecycleBeanPostProcessor" />
</beans>
```

​	4、编写自定义realm类，重写授权doGetAuthorizationInfo和认证doGetAuthenticationInfo两个方法：

```
package com.how2java.realm;
 
import java.util.Set;
 
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.codec.CodecException;
import org.apache.shiro.crypto.UnknownAlgorithmException;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
 
import com.how2java.pojo.User;
import com.how2java.service.PermissionService;
import com.how2java.service.RoleService;
import com.how2java.service.UserService;
 
public class DatabaseRealm extends AuthorizingRealm {
 
    @Autowired
    private UserService userService;
    @Autowired
    private RoleService roleService;
    @Autowired
    private PermissionService permissionService;
     
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //能进入到这里，表示账号已经通过验证了
        String userName =(String) principalCollection.getPrimaryPrincipal();
        //通过service获取角色和权限
        Set<String> permissions = permissionService.listPermissions(userName);
        Set<String> roles = roleService.listRoleNames(userName);
         
        //授权对象
        SimpleAuthorizationInfo s = new SimpleAuthorizationInfo();
        //把通过service获取到的角色和权限放进去
        s.setStringPermissions(permissions);
        s.setRoles(roles);
        return s;
    }
 
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        //获取账号密码
        UsernamePasswordToken t = (UsernamePasswordToken) token;
        String userName= token.getPrincipal().toString();
        //获取数据库中的密码
        User user =userService.getByName(userName);
        String passwordInDB = user.getPassword();
        String salt = user.getSalt();
        //认证信息里存放账号密码, getName() 是当前Realm的继承方法,通常返回当前类名 :databaseRealm
        //盐也放进去
        //这样通过applicationContext-shiro.xml里配置的 HashedCredentialsMatcher 进行自动校验
        SimpleAuthenticationInfo a = new SimpleAuthenticationInfo(userName,passwordInDB,ByteSource.Util.bytes(salt),getName());
        return a;
    }
 
}
```

​	5、URL权限配置，PathMatchingFilter 是shiro 内置过滤器PathMatchingFilter 继承了这个它。
基本思路如下：

1. 如果没登录就跳转到登录
2. 如果当前访问路径没有在权限系统里维护，则允许访问
	. 当前用户所拥有的权限如何不包含当前的访问地址，则跳转到/unauthorized，否则就允许访问	

```
package com.how2java.filter;
 
import java.util.Set;
 
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
 
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.PathMatchingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.beans.factory.annotation.Autowired;
 
import com.how2java.service.PermissionService;
 
public class URLPathMatchingFilter extends PathMatchingFilter {
    @Autowired
    PermissionService permissionService;
 
    @Override
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue)
            throws Exception {
        String requestURI = getPathWithinApplication(request);
 
        System.out.println("requestURI:" + requestURI);
 
        Subject subject = SecurityUtils.getSubject();
        // 如果没有登录，就跳转到登录页面
        if (!subject.isAuthenticated()) {
            WebUtils.issueRedirect(request, response, "/login");
            return false;
        }
 
        // 看看这个路径权限里有没有维护，如果没有维护，一律放行(也可以改为一律不放行)
        boolean needInterceptor = permissionService.needInterceptor(requestURI);
        if (!needInterceptor) {
            return true;
        } else {
            boolean hasPermission = false;
            String userName = subject.getPrincipal().toString();
            Set<String> permissionUrls = permissionService.listPermissionURLs(userName);
            for (String url : permissionUrls) {
                // 这就表示当前用户有这个权限
                if (url.equals(requestURI)) {
                    hasPermission = true;
                    break;
                }
            }
 
            if (hasPermission)
                return true;
            else {
                UnauthorizedException ex = new UnauthorizedException("当前用户没有访问路径 " + requestURI + " 的权限");
 
                subject.getSession().setAttribute("ex", ex);
 
                WebUtils.issueRedirect(request, response, "/unauthorized");
                return false;
            }
 
        }
 
    }
}
```

​	6、执行com.how2java.sql中的shiro.sql，利用mybaits的逆向工程生成相应的pojo和mapper等源码，具体的SSM配置在此不做详细介绍。