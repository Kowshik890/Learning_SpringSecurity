# Spring Security Learning Topics

### This tutorial is learned from this resource: [Spring Security by Amigoscode](https://www.youtube.com/watch?v=her_7pa0vrg&t=2559s)

### FORM BASED AUTHENTICATION
* WebSecurityConfigurerAdapter()
### BASIC AUTH
* Basic AUTH Overview
	[![Screenshot-2022-10-16-at-16-13-43.png](https://i.postimg.cc/dDcMwwHS/Screenshot-2022-10-16-at-16-13-43.png)](https://postimg.cc/xN5pPDSK)

* configure(http: HttpSecurity): void
  * .authorizeRequest()
  * .anyRequest()
  * .authenticated()
  * .and()
  * .httpBasic();
  
* N.B: The Drawback of BASIC AUTH is, there is no way of logging out.
       Because, username and password are sent in every single request. 
       And, for every single request, server has to validate whether the username and password is correct or not.
### Ant Machers 
* to White List URLs
* .antMatchers("/", "index", "/css/*", "/js/*") 
* .permitAll()
### IN MEMORY USER DETAILS MANAGER
* userDetailsService()
  * UserDetails <userName> = User.buider() // Both UserDetails & User classes belong to "springbootframework.security"
  * .username("<username>")
    .password("password")
    .roles("STUDENT")  // internally - ROLE_STUDENT
    .build();
  * InMemoryUserDetailsManager(<userName>);
 ### PASSWORD ENCODE WITH BCRYPT
 * Create a class named "PasswordConfig"
 * PasswordEncoder passwordEncoder() 
 * BCryptPasswordEncoder(strength: 10);
 * .password(passwordEncoder.encode("password"))  // to encode the given password using BCRYPT Encoder
 ### ROLES & PERMISSIONS USING ENUMS
 * Create an ENUM class "ApplicationUserRole"
  * use "Sets.newHashSet()" function to set role
  * create "Set<ApplicationUserPermission>" type variable to permit for specific role
  * make a constructor and getter method
 * Create an ENUM class for permission, "ApplicationUserPermission"
  * make a constructor, getter method and declare the permissions.
 ### PROTECT API using ROLE BASED AUTHENTICATION
 * antMatchers("/api/**").hasRole(STUDENT.name())
  * only student can access the API. E.g: "/api/v1/students/1" 
 ### PERMISSION BASED AUTHENTICATION
 * hasAuthorithy()
   * .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
   * .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
   * .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
 
   => Here, those who has the permission in COURSE_WRITE, only s/he has the access to do "Delete/Put/Post" 
   * .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRINEE.name())
 
   => Here, both ADMIN & ADMINTRAINEE has the Role to access the GET Method
 * Adding Authorities to User
   * First step is to create a public function "Set<SimpleGrantedAuthority>" type to make ".map()" & ".collect()" and add the permission on the basis of Role_"Name"
 
 ```
    public Set<SimpleGrantedAuthority> getGrantedAuthority () {
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissions;
    }
 ```
 
   * Second step is to add ".authority()" instead of ".roles()" in "ApplicationSecurityConfig" class inside "UserDetailsService userDetailsService()" function 
   * E.G: .authorities(ROLE_NAME.getGrantedAuthority())   // ADMIN, STUDENT, ...
 ### ORDER of ANTMATCHERS
 * Order of antMatchers must be maintained carefully while giving permission to the respective roles
 ### PREAUTHORIZE() ANNOTATION
 * PreAuthorize() annotation can be used instead of antMatchers()
 * First use "@EnableGlobalMethodSecurity(prePostEnabled = true)" annotation in "ApplicationSecurityConfig" class 
 * In "StudentManagementController" use "@PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")" annotation under "@GetMapping" annotation  // for both ADMIN & ADMINTRAINEE
 * "@PreAuthorize("hasAuthority('student:write')")" annotation under "@PostMapping", "@PutMapping" & "@DeleteMapping",   // for only ADMIN 
 ### CSRF Token (For Browser Clients)
 * [When to use CSRF protection](https://docs.spring.io/spring-security/site/docs/5.0.x/reference/html/csrf.html#when-to-use-csrf-protection)
 * During using POSTMAN, add "Postman Interceptor" extension to browser. Then activate interceptor from POSTMAN.
 * Get "XSRF-TOKEN" from "Cookies". Then, in Headers, add "X-XSRF-TOKEN" and paste the value.
 * In "ApplicationSecurityConfig" add these below two lines instead of ".csrf().disable()"
 ```
    .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())   // that is used by browser clients
    .and()   // that is used by browser clients
 ```
 
 ### CUSTOM LOGIN PAGE (Based on FORM BASED AUTHENTICATION)
 * Comment ".httpBasic()" and add ".formLogin()" from "ApplicationSecurityConfig" class
 * For Login (Custom) Page
   * in pom.xml file add "thymeleaf" as dependency
   * create "templates" folder inside "resources"
   * inside "templates" folder create custom login page
   * to access "login.html", create "TemplateController"
   * N.B: return "String" should be same as custom login page file name. E.g: "login"
   * lastly, add ".loginPage("/login").permitAll();"  // Here, "/login" is written according to "TemplateController" GetMapping path
 * redirect after login
   * create a method for the redirected page (e.g: courses)
   * create a html file for that page/path
   * add the path in "ApplicationSecurityConfig" class by ".defaultSuccessUrl("/courses", true)"
 ### REMEMBER ME with COOKIE & SESSION ID
 ```
    .and()
    .rememberMe()
        .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
        .key("somethingverysecured"); // default to 2 weeks
 ```
 ### LOGOUT
 ```
    .and()
    .logout()
        .logoutUrl("/logout")
        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))  // it has to use only when .csrf().disable()
        .clearAuthentication(true)
        .invalidateHttpSession(true)
        .deleteCookies("JSESSIONID", "remember-me")
        .logoutSuccessUrl("/login");
 ```
 ### JSON WEB TOKEN (JWT)
 JWT is a means of transmitting information between two parties in a compact, verifiable form.
 * Add these dependencies in pom.xml file to execute JWT
 ```
    <dependency>
      <groupId>io.jsonwebtoken</groupId>
      <artifactId>jjwt-api</artifactId>
      <version>0.11.2</version>
    </dependency>
		
    <dependency>
      <groupId>io.jsonwebtoken</groupId>
      <artifactId>jjwt-impl</artifactId>
      <version>0.11.2</version>
      <scope>runtime</scope>
    </dependency>

    <dependency>
      <groupId>io.jsonwebtoken</groupId>
      <artifactId>jjwt-jackson</artifactId> <!-- or jjwt-gson if Gson is preferred -->
      <version>0.11.2</version>
      <scope>runtime</scope>
    </dependency>
 ```
 * JwtUsernameAndPasswordAuthenticationFilter - attemptAuthentication()
   * to verified the credentials create a class "JwtUsernameAndPasswordAuthenticationFilter"
   * override "attemptAuthentication()" method in that class
   * for more understanding, go to "[JwtUsernameAndPasswordAuthenticationFilter](https://github.com/Kowshik890/Learning_SpringSecurity/blob/main/SpringSecurityPractice/src/main/java/com/example/SpringSecurityPractice/jwt/JwtUsernameAndPasswordAuthenticationFilter.java)" file
   * create another class "UsernameAndPasswordAuthenticationRequest" 
 * JwtUsernameAndPasswordAuthenticationFilter - successfulAuthentication()
   * inside "JwtUsernameAndPasswordAuthenticationFilter" class, override "successfulAuthentication()" method
   * after validates credentials successfully, sends token to the client
   * for more understanding, go to "[JwtUsernameAndPasswordAuthenticationFilter](https://github.com/Kowshik890/Learning_SpringSecurity/blob/main/SpringSecurityPractice/src/main/java/com/example/SpringSecurityPractice/jwt/JwtUsernameAndPasswordAuthenticationFilter.java)" file
 * Filters and Stateless Sessions
   * in "ApplicationSecurityConfig" class while switching from form based authentication with extension of Session to JWT token based authentication, following functions don't need
      - formLogin()
      - rememberMe()
      - logout()
   * add these lines to configure JWT Token based Authentication
   ```
      .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
      .and()
      .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager()))
   ```
 * JWT Token Verifier Filter
	* to validate token, whether it is still valid or not by server while sending a token for every single request by client
	* create a filter name "JwtTokenVerifier" where the task of this filter is to check whether the token is valid or not
 	* add ".addFilterAfter(new JwtTokenVerifier(), JwtUsernameAndPasswordAuthenticationFilter.class)" in "ApplicationSecurityConfig" class

 
 
 
 
 
