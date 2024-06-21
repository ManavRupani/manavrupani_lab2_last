package com.example.coffeshop_app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;

@Service
public class OrderService {

    @Autowired
    private OrderRepository orderRepository;

    @Autowired
    private OrderDetailRepository orderDetailRepository;

    @Transactional
    public void saveOrderWithDetails(List<CartItem> cartItems, User user) {
        // Calculate total amount
        double totalAmount = cartItems.stream().mapToDouble(CartItem::getTotalAmount).sum();

        // Save order
        Order order = new Order();
        order.setUserId(user.getId());
        order.setDate(LocalDate.now());
        order.setTotalAmount(totalAmount);
        orderRepository.save(order);

        // Save order details
        for (CartItem cartItem : cartItems) {
            OrderDetail orderDetail = new OrderDetail();
            orderDetail.setOrderId(order.getId());
            orderDetail.setItem(cartItem.getName());
            orderDetail.setImage(cartItem.getImage());
            orderDetail.setPrice(cartItem.getPrice());
            orderDetail.setQuantity(cartItem.getQuantity());
            orderDetail.setUserId(user.getId());
            orderDetailRepository.save(orderDetail);
        }
    }

    public List<Order> getOrdersByUserId(Long userId) {
        return orderRepository.findByUserId(userId);
    }


    public Order getOrderById(Long id) {
        return orderRepository.findById(id).orElse(null);
    }
}
