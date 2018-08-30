package com.kadan.accountservice.web;

//import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Created by lijunjie on 2018/7/29.
 */

//@FeignClient(name = "BOOKMARK-SERVICE")
public interface BookmarkService {

    @RequestMapping(path = "/kadan/bookmarks",method = RequestMethod.GET)
    public String getBookMarks();
}
