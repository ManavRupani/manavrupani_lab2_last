package com.example.coffeshop_app;

import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/")
public class HomeController {

    @Autowired
    private OrderService orderService;

    @Autowired
    private OrderDetailRepository orderDetailRepository;

    @GetMapping("/")
    public String home(HttpSession session, Model model) {
        List<CartItem> cartItems = (List<CartItem>) session.getAttribute("cartItems");
        if (cartItems == null) {
            cartItems = new ArrayList<>();
        }

        User user = (User) session.getAttribute("user");
        if (user != null) {
            model.addAttribute("user", user);

        }

        model.addAttribute("cartItems", cartItems);
        model.addAttribute("cartQty", cartItems.size());
        model.addAttribute("total", calculateTotal(cartItems));
        return "home";
    }

    @PostMapping("/add")
    public String addToCart(@RequestParam String item, @RequestParam String image, @RequestParam double price, HttpSession session) {
        List<CartItem> cartItems = (List<CartItem>) session.getAttribute("cartItems");
        if (cartItems == null) {
            cartItems = new ArrayList<>();
            session.setAttribute("cartItems", cartItems);
        }

        boolean itemExists = false;
        for (CartItem cartItem : cartItems) {
            if (cartItem.getName().equals(item)) {
                cartItem.setQuantity(cartItem.getQuantity() + 1);
                itemExists = true;
                break;
            }
        }

        if (!itemExists) {
            cartItems.add(new CartItem(item, image, price));
        }

        return "redirect:/";
    }

    @PostMapping("/remove")
    public String removeFromCart(@RequestParam int index, HttpSession session) {
        List<CartItem> cartItems = (List<CartItem>) session.getAttribute("cartItems");
        if (cartItems != null && index >= 0 && index < cartItems.size()) {
            cartItems.remove(index);
        }
        return "redirect:/cart";
    }

    private double calculateTotal(List<CartItem> cartItems) {
        double total = 0;
        for (CartItem item : cartItems) {
            total += item.getTotalAmount();
        }
        return total;
    }

    @GetMapping("/cart")
    public String cart(HttpSession session, Model model) {
        List<CartItem> cartItems = (List<CartItem>) session.getAttribute("cartItems");
        if (cartItems == null) {
            cartItems = new ArrayList<>();
        }
        model.addAttribute("cartItems", cartItems);
        model.addAttribute("cartQty", cartItems.size());

        User user = (User) session.getAttribute("user");
        if (user != null) {
            model.addAttribute("user", user);

        }

        double totalAmount = calculateTotal(cartItems);
        DecimalFormat df = new DecimalFormat("#0.00");
        String formattedTotal = df.format(totalAmount);

        model.addAttribute("total",formattedTotal);


        return "cart";
    }


    @GetMapping("/payment")
    public String payment(HttpSession session, Model model) {

        List<CartItem> cartItems = (List<CartItem>) session.getAttribute("cartItems");
        if (cartItems == null) {
            cartItems = new ArrayList<>();
        }
        model.addAttribute("cartItems", cartItems);
        model.addAttribute("cartQty", cartItems.size());

        double totalAmount = calculateTotal(cartItems);
        DecimalFormat df = new DecimalFormat("#0.00");
        String formattedTotal = df.format(totalAmount);

        model.addAttribute("total",formattedTotal);

        User user = (User) session.getAttribute("user");
        if (user != null) {
            model.addAttribute("user", user);

        }


        return "payment";
    }

    @GetMapping("/success")
    public String success(HttpSession session, Model model) {
        User user = (User) session.getAttribute("user");
        if (user != null) {
            model.addAttribute("user", user);

            // Retrieve cart items from session
            List<CartItem> cartItems = (List<CartItem>) session.getAttribute("cartItems");

            // Check if cart items list is not null
            if (cartItems != null) {
                // Save order to database and clear the cart
                orderService.saveOrderWithDetails(cartItems, user);

                // Clear the cart items list
                cartItems.clear();
            }

            // Save the cleared list back to the session (optional, as the list is already in session)
            session.setAttribute("cartItems", cartItems);

            return "success";
        } else {
            return "redirect:/login";
        }
    }

    @GetMapping("/my-orders")
    public String myOrders(HttpSession session, Model model) {
        User user = (User) session.getAttribute("user");
        if (user != null) {
            List<Order> orders = orderService.getOrdersByUserId(user.getId());
            model.addAttribute("user", user);
            model.addAttribute("orders", orders);
            return "my-orders";
        } else {
            return "redirect:/login";
        }
    }

    @GetMapping("/order-detail/{id}")
    public String orderDetail(@PathVariable Long id, HttpSession session, Model model) {
        User user = (User) session.getAttribute("user");
        if (user != null) {
            Order order = orderService.getOrderById(id);
            if (order != null && order.getUserId().equals(user.getId())) {
                // Fetch order details from OrderDetailRepository
                List<OrderDetail> orderDetails = orderDetailRepository.findByOrderId(order.getId());

                model.addAttribute("order", order);
                model.addAttribute("orderDetails", orderDetails); // Add orderDetails to model
                model.addAttribute("user", user);
                return "order-detail";
            } else {
                return "redirect:/my-orders";
            }
        } else {
            return "redirect:/login";
        }
    }
}
