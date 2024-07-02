package com.example.coffeshop_app.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.coffeshop_app.entity.User;
import com.example.coffeshop_app.jwt.JWTUtil;
import com.example.coffeshop_app.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Controller
public class UserController {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JWTUtil jwtUtil;
    

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping("/login")
    public String loginUser(User user, HttpServletRequest request, RedirectAttributes redirectAttributes) {
        User existingUser = userRepository.findByEmail(user.getEmail());
        if (existingUser != null && passwordEncoder.matches(user.getPassword(), existingUser.getPassword())) {
            String token = jwtUtil.generateToken(existingUser.getEmail());
            request.getSession().setAttribute("token", token); // Store token in session
            if (existingUser.getType().equals("user")) {
                return "redirect:/user-detail";
            } else if (existingUser.getType().equals("admin")) {
                return "redirect:/admin-detail";
            }
        }
        return "redirect:/login?error";
    }

    @GetMapping("/signup")
    public String signup() {
        return "signup";
    }

    @PostMapping("/signup")
    public String signupUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return "redirect:/login";
    }

    @GetMapping("/user-detail")
    public String userDetail(HttpServletRequest request) {
        String token = (String) request.getSession().getAttribute("token");
        if (token != null && jwtUtil.validateToken(token)) {
            return "user-detail";
        } else {
            return "redirect:/login";
        }
    }

    @GetMapping("/admin-detail")
    public String adminDetail(HttpServletRequest request) {
        String token = (String) request.getSession().getAttribute("token");
        if (token != null && jwtUtil.validateToken(token)) {
            return "admin-detail";
        } else {
            return "redirect:/login";
        }
    }

    @GetMapping("/api/view-token")
    @ResponseBody
    public ResponseEntity<String> viewToken(HttpServletRequest request) {
        String token = (String) request.getSession().getAttribute("token");
        if (token != null && jwtUtil.validateToken(token)) {
            return ResponseEntity.ok(token);
        } else {
            return ResponseEntity.status(401).body("Unauthorized");
        }
    }
    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        return "redirect:/login";
    }
}
