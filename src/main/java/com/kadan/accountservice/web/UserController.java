package com.kadan.accountservice.web;

//import com.netflix.discovery.converters.Auto;
//import com.netflix.hystrix.contrib.javanica.annotation.HystrixCommand;
//import com.netflix.hystrix.contrib.javanica.annotation.HystrixProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/demo")
public class UserController {

    private static Logger logger = LoggerFactory.getLogger(UserController.class);


    @Value ("${hello}")
    private String hello;
    @Value ("${jasypt.encryptor.password}")
    private String jasypEncryptKey;
    @Value ("${myapp.database.password}")
    private String databasePassword;


    @RequestMapping(value = "/log", method = RequestMethod.GET)
    public ResponseEntity<String> demo(){
        logger.trace("This is the TRACE log.");
        logger.debug("This is the DEBUG log.");
        logger.warn("This is the WARN log.");
        logger.info("This is the INFO log");
        logger.error("This is the ERROR log.");
        return ResponseEntity.ok("You've made it if you hit this !!!");
    }

    @RequestMapping(value = "/config", method = RequestMethod.GET)
    public ResponseEntity<String> demo_config(){

        return ResponseEntity.ok(" Here is your database password >>> " + databasePassword + " | " +
        " And here is the encryption key >>> " + jasypEncryptKey);
    }

//    @Autowired
//    RestTemplate restTemplate;
//
//    @Autowired
//    BookmarkService bookmarkService;
//
//    @RequestMapping(path = "/feignBookmarks_1",method = RequestMethod.GET)
//    public String getBookmarks_feign_1(){
//        return "hello world";
//    }
//
//    @RequestMapping(path = "/feignBookmarks",method = RequestMethod.GET)
//    public String getBookmarks_feign(){
//        return bookmarkService.getBookMarks();
//    }

//    @LoadBalanced
//    @RequestMapping(path="/bookmarks",method = RequestMethod.GET)
//    @HystrixCommand(commandProperties = {
//            @HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "1000"),
//            @HystrixProperty(name = "execution.timeout.enabled", value = "false")},fallbackMethod = "testRibbonFailure")
//    public String testRibbon(){
//        System.out.println("now here you are");
//        return this.restTemplate.getForEntity("http://bookmark-service/kadan/bookmarks",String.class).getBody();
//    }
//
//    public String testRibbonFailure(){
//        return "bookmark service's down. ";
//    }





}
