# Learning_SpringSecurity
### Day 1:
* WebSecurityConfigurerAdapter()
* configure(http: HttpSecurity): void
  * .authorizeRequest()
  * .anyRequest()
  * .authenticated()
  * .and()
  * .httpBasic();
* Ant Machers (to White List URLs)
  * .antMatchers("/", "index", "/css/*", "/js/*")
  * .permitAll()

### Day 2:
