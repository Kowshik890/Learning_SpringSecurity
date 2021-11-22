# Spring Security Learning Topics
### FORM BASED AUTHENTICATION
* WebSecurityConfigurerAdapter()
### BASIC AUTH
* configure(http: HttpSecurity): void
  * .authorizeRequest()
  * .anyRequest()
  * .authenticated()
  * .and()
  * .httpBasic();
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
 
 
