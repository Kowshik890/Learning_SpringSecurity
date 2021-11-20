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
