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
--> to White List URLs
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
