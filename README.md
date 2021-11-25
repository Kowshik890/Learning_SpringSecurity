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
