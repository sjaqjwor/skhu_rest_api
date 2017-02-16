package kr.ac.skhu.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import kr.ac.skhu.model.security.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mobile.device.Device;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtTokenUtil implements Serializable {

    private static final long serialVersionUID = -3301605591108950415L;
    // 토큰 payload 부분에 저장할 변수들
    static final String CLAIM_KEY_LOGINID = "loginId";
    static final String CLAIM_KEY_USERNAME = "name";
    static final String CLAIM_KEY_AUDIENCE = "audience";
    static final String CLAIM_KEY_CREATED = "created";
    static final String CLAIM_KEY_COUNT = "count";
    /* 기기 타입 변수들 */
    private static final String AUDIENCE_UNKNOWN = "unknown";
    private static final String AUDIENCE_WEB = "web";
    private static final String AUDIENCE_MOBILE = "mobile";
    private static final String AUDIENCE_TABLET = "tablet";

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;
    /* 토큰을 claim 형태로 변환하여 내부의 loginId 값을 추출해낸다. */
    public String getLoginIdFromToken(String token) {
        String loginId;
        try {
            final Claims claims = getClaimsFromToken(token);
            loginId = claims.get(CLAIM_KEY_LOGINID).toString();
        } catch (Exception e) {
            loginId = null;
        }
        return loginId;
    }
    /* 토큰을 claim 형태로 변환하여 내부의 username 값을 추출해낸다. */
    public String getUsernameFromToken(String token) {
        String username;
        try {
            final Claims claims = getClaimsFromToken(token);
            username = claims.getSubject();
        } catch (Exception e) {
            username = null;
        }
        return username;
    }
    /* 토큰을 claim 형태로 변환하여 토큰이 생성된 시간을 추출해낸다.*/
    public Date getCreatedDateFromToken(String token) {
        Date created;
        try {
            final Claims claims = getClaimsFromToken(token);
            created = new Date((Long) claims.get(CLAIM_KEY_CREATED));
        } catch (Exception e) {
            created = null;
        }
        return created;
    }
    /* 토큰을 claim 형태로 변환하여 토큰의 유효시간을 추출해낸다. */
    public Date getExpirationDateFromToken(String token) {
        Date expiration;
        try {
            final Claims claims = getClaimsFromToken(token);
            expiration = claims.getExpiration();
        } catch (Exception e) {
            expiration = null;
        }
        return expiration;
    }
    /* 토큰에 설정된 audience 를 반환한다. */
    public String getAudienceFromToken(String token) {
        String audience;
        try {
            final Claims claims = getClaimsFromToken(token);
            audience = (String) claims.get(CLAIM_KEY_AUDIENCE);
        } catch (Exception e) {
            audience = null;
        }
        return audience;
    }
    /* Token 을 claim 형태로 파싱한다. */
    private Claims getClaimsFromToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            claims = null;
        }
        return claims;
    }
    /* 현재 시간 기준, 설정해 놓은 expiration*1000 이후까지 토큰의 유효시간을 설정한다. */
    private Date generateExpirationDate() {
        return new Date(System.currentTimeMillis() + expiration * 1000);
    }
    /* 토큰 유효시간이 남아있는지 확인한다. */
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }
    /* 가장 최근 비밀번호 변경 시간보다, 토큰을 발급한게 이전인지 확인한다. */
    private Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
        return (lastPasswordReset != null && created.before(lastPasswordReset));
    }
    /* device 타입을 확인하여, audience 에 대입한다. */
    private String generateAudience(Device device) {
        String audience = AUDIENCE_UNKNOWN;
        if (device.isNormal()) {
            audience = AUDIENCE_WEB;
        } else if (device.isTablet()) {
            audience = AUDIENCE_TABLET;
        } else if (device.isMobile()) {
            audience = AUDIENCE_MOBILE;
        }
        return audience;
    }

    private Boolean ignoreTokenExpiration(String token) {
        String audience = getAudienceFromToken(token);
        return (AUDIENCE_TABLET.equals(audience) || AUDIENCE_MOBILE.equals(audience));
    }
    /* 토큰 발급 메소드 claim 형태로 필요한 정보들을 넣을 수 있다.*/
    public String generateToken(UserDetails userDetails, User user, Device device) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_KEY_LOGINID, user.getLoginId()); //로그인 아이디
        claims.put(CLAIM_KEY_USERNAME, userDetails.getUsername()); //유저 이름
        claims.put(CLAIM_KEY_AUDIENCE, generateAudience(device)); //접속한 클라이언트 기기의 정보
        claims.put(CLAIM_KEY_CREATED, new Date());
        claims.put(CLAIM_KEY_COUNT,user.getCount()); //최초 로그인인지
        return generateToken(claims);
    }
    /* 위의 claim Map 정보를 매개변수로 받아 jwt 발급한다.*/
    String generateToken(Map<String, Object> claims) {
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(generateExpirationDate())
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }
    /* refresh 토큰을 발급하기 적절한지 조건을 확인한다*/
    public Boolean canTokenBeRefreshed(String token, Date lastPasswordReset) {
        final Date created = getCreatedDateFromToken(token);
        return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset)
                && (!isTokenExpired(token) || ignoreTokenExpiration(token));
    }
    /* refresh 토큰을 발급하는 메소드 */
    public String refreshToken(String token) {
        String refreshedToken;
        try {
            final Claims claims = getClaimsFromToken(token);
            claims.put(CLAIM_KEY_CREATED, new Date());
            refreshedToken = generateToken(claims);
        } catch (Exception e) {
            refreshedToken = null;
        }
        return refreshedToken;
    }
    /* 토큰이 유효한지 확인하는 메소드 unique 한 loginId 이용*/
    public Boolean validateToken(String token, UserDetails userDetails) {
        JwtUser user = (JwtUser) userDetails;
        final String loginId = getLoginIdFromToken(token);
        final Date created = getCreatedDateFromToken(token);
        return (
                loginId.equals(user.getLoginId())
                        && !isTokenExpired(token)
                        && !isCreatedBeforeLastPasswordReset(created, user.getBirth()));
    }
}