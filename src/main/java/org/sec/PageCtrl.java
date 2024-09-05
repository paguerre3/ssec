package org.sec;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageCtrl {
    @GetMapping({"/welcome", "/home"})
    public String handleWelcome() {
        return "welcome";
    }

    @GetMapping("/admin/home")
    public String handleAdminHome() {
        return "admin_home";
    }

    @GetMapping("/user/home")
    public String handleUserHome() {
        return "user_home";
    }
}
