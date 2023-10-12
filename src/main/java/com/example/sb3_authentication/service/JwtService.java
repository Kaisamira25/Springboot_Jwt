package com.example.sb3_authentication.service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtService {

    public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";
    // Secret-Key dùng để tao chữ ký (signature) cho JWT token
    public String generateToken(String userName) { // Phương thức này để tạo một token bằng cách nhận vào 1 tham số userName
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userName);
    }

    private String createToken(Map<String, Object> claims, String userName) { // Phương thức tạo token
        return Jwts.builder() // bắt đầu build một Jwt token
                .setClaims(claims) // từ tham số claims là một map setClaims sẽ tạo ra một claims với kiểu Map
                .setSubject(userName) // setSubject là tạo ra một trường sub để chứa giá trị là userName ví dụ : "sub": "userName"
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30)) // dòng này sẽ set thời gian hết hạn với gia trị là mili giây
                .signWith(getSignKey(), SignatureAlgorithm.HS256) // dòng này sẽ sử dụng secret key và tham số thứ 2 là một "phép toán"
                .compact(); // tạo ra một token và trả về token đó
    }

    private Key getSignKey() { // đây là phương thức để giải mã secret key và sau đó sẽ được dùng cho phương thức createToken để tạo ra token
        byte[] keyBytes= Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUsername(String token) { // phương thức này có tác dụng sẽ giải mã Claims trong payload của jwt token và lấy ra username
        return extractClaim(token, Claims::getSubject); // giải mã bằng cách sử dụng hàm extractClaim
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) { // hàm này sẽ nhận vào token và giải mã để có được dữ liệu từ payload của một jwt token
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) { // phương thức này dùng để xác thực một token và khi đã xác thực thì nó sẽ tiến hay giãi mã payload của token sau đó sử dụng
        // dữ liệu đó cho các hành động khác
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token) { // check hạn dùng của token
        // nhận tham số là một chuỗi token
        return extractExpiration(token).before(new Date()); // sử dụng phương thức giải mã hạn dùng từ Claims trong token và .before để check xem nó có quá hạn ngày hôm nay không
    }

    public Boolean validateToken(String token, UserDetails userDetails) { // phương thức này để xác minh token bằng 2 tham số là token và thông tin người dùng
        final String username = extractUsername(token); // 1 biến username sẽ chứ thông tin người dùng muốn xác minh đuọc lấy ra bằng cách sử dụng extractUsername để có được thông tin
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token)); // trả về kiểu boolean phù hợp
    }


}
