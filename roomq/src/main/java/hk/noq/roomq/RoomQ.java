package hk.noq.roomq;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

public class RoomQ {

  private final String clientID;
  private final String jwtSecret;
  private final String ticketIssuer;
  private final String statusEndpoint;
  private final String tokenName;
  private String token;
  private final boolean debug;
  private final CookieConfig cookieConfig;

  public RoomQ(String clientID, String jwtSecret, String ticketIssuer, String statusEndpoint, boolean debug) {
    this(clientID, jwtSecret, ticketIssuer, statusEndpoint, debug, new CookieConfig());
  }

  public RoomQ(String clientID, String jwtSecret, String ticketIssuer, String statusEndpoint, boolean debug, CookieConfig cookieConfig) {
    if (cookieConfig == null) throw new IllegalArgumentException("cookieConfig must not be null");
    this.clientID = clientID;
    this.jwtSecret = jwtSecret;
    this.ticketIssuer = ticketIssuer;
    this.statusEndpoint = statusEndpoint;
    this.debug = debug;
    this.tokenName = "be_roomq_t_" + clientID;
    this.cookieConfig = cookieConfig;
  }

  public Locker getLocker(HttpServletRequest request, String apiKey, String url)
  {
    return new Locker(clientID, apiKey, getToken(request), url);
  }


  public ValidationResult validate(HttpServletRequest request, HttpServletResponse response, String returnURL, String sessionId) {
    String token = getToken(request);
    boolean needGenerateJWT = false;
    boolean needRedirect = false;

    String currentURL = request.getScheme() + "://" +
            request.getServerName() +
            ("http".equals(request.getScheme()) && request.getServerPort() == 80 || "https".equals(request.getScheme()) && request.getServerPort() == 443 ? "" : ":" + request.getServerPort()) +
            request.getRequestURI() +
            (request.getQueryString() != null ? "?" + request.getQueryString() : "");

    if (token == null) {
      needGenerateJWT = true;
      needRedirect = true;
      debugPrint("no jwt");
    } else {
      debugPrint("current jwt " + token);

      try {
        Algorithm algorithm = Algorithm.HMAC256(jwtSecret);
        JWTVerifier verifier = JWT.require(algorithm)
                .acceptLeeway(Long.MAX_VALUE)
                .build();
        DecodedJWT jwt = verifier.verify(token);
        if (sessionId != null && !jwt.getClaim("session_id").asString().equals(sessionId)) {
          needGenerateJWT = true;
          needRedirect = true;
          debugPrint("session id not match");
        } else if (!jwt.getClaim("deadline").isNull() && jwt.getClaim("deadline").asLong() < System.currentTimeMillis() / 1000) {
          needRedirect = true;
          debugPrint("deadline exceed");
        } else if ("queue".equals(jwt.getClaim("type").asString())) {
          needRedirect = true;
          debugPrint("in queue");
        } else if ("self-sign".equals(jwt.getClaim("type").asString())) {
          needRedirect = true;
          debugPrint("self sign token");
        }
      } catch (Exception $ex) {
        needGenerateJWT = true;
        needRedirect = true;
        debugPrint("invalid secret");
      }

    }

    if (needGenerateJWT) {
      token = generateJWT(sessionId);
      debugPrint("generating new jwt " + token);
    }

    response.addCookie(createTokenCookie(token));
    if (needRedirect) {
      return redirectToTicketIssuer(token, returnURL != null ? returnURL : currentURL);
    } else {
      return enter(currentURL);
    }
  }

  public void extend(HttpServletRequest request, HttpServletResponse response, long duration) throws QueueStoppedException, HTTPRequestException, InvalidTokenException, NotServingException {
    String backend = getBackend();

    try {
      Map<String, Object> data = new HashMap<>();
      data.put("action", "beep");
      data.put("client_id", clientID);
      data.put("id", getToken(request));
      data.put("extend_serving_duration", duration * 60);

      Map<String, Object> res = Utils.sendHTTPRequest("POST", "https://" + backend + "/queue/" + clientID, data);
      token = (String) res.get("id");
      response.addCookie(createTokenCookie(token));
    } catch (HTTPRequestException e) {
      if (e.getStatusCode() == 401) {
        throw new InvalidTokenException();
      } else if (e.getStatusCode() == 404) {
        throw new NotServingException();
      }
      throw e;
    }
  }

  public long getServing(HttpServletRequest request) throws QueueStoppedException, HTTPRequestException, InvalidTokenException, NotServingException {
    String backend = getBackend();

    try {
      Map<String, Object> res = Utils.sendHTTPRequest("GET", "https://" + backend + "/rooms/" + clientID + "/servings/" + getToken(request), new HashMap<>());
      return (long) res.get("deadline");
    } catch (HTTPRequestException e) {
      if (e.getStatusCode() == 401) {
        throw new InvalidTokenException();
      } else if (e.getStatusCode() == 404) {
        throw new NotServingException();
      }
      throw e;
    }
  }

  public void deleteServing(HttpServletRequest request, HttpServletResponse response) throws QueueStoppedException, HTTPRequestException, InvalidTokenException, NotServingException {
    String backend = getBackend();

    try {
      Map<String, Object> data = new HashMap<>();
      data.put("action", "delete_serving");
      data.put("client_id", clientID);
      data.put("id", getToken(request));

      Map<String, Object> res = Utils.sendHTTPRequest("POST", "https://" + backend + "/queue/" + clientID, data);
      token = (String) res.get("id");
      response.addCookie(createTokenCookie(token));
    } catch (HTTPRequestException e) {
      if (e.getStatusCode() == 401) {
        throw new InvalidTokenException();
      } else if (e.getStatusCode() == 404) {
        throw new NotServingException();
      }
      throw e;
    }
  }

  private Cookie createTokenCookie(String token) {
    Cookie cookie = new Cookie(tokenName, token);
    cookie.setMaxAge(cookieConfig.getMaxAge());
    if (cookieConfig.getHttpOnly() != null) cookie.setHttpOnly(cookieConfig.getHttpOnly());
    if (cookieConfig.getSecure() != null) cookie.setSecure(cookieConfig.getSecure());
    if (cookieConfig.getPath() != null) cookie.setPath(cookieConfig.getPath());
    if (cookieConfig.getDomain() != null) cookie.setDomain(cookieConfig.getDomain());
    // if (cookieConfig.getSameSite() != null) cookie.setAttribute("SameSite", cookieConfig.getSameSite());
    return cookie;
  }

  private String getBackend() throws QueueStoppedException, HTTPRequestException {
    Map<String, Object> response = Utils.sendHTTPRequest("GET", statusEndpoint + "/" + clientID, new HashMap<>());
    if ("stopped".equals(response.get("state"))) {
      throw new QueueStoppedException();
    }
    return (String) response.get("backend");
  }

  private String getToken(HttpServletRequest request) {
    String token = request.getParameter("noq_t");
    if (token == null) {
      Cookie[] cookies = request.getCookies();
      if (cookies != null) {
        Optional<Cookie> tokenInCookies = Arrays.stream(cookies).filter(cookie -> cookie.getName().equals(tokenName)).findFirst();
        if (tokenInCookies.isPresent()) {
          token = tokenInCookies.get().getValue();
        }
      }
    }
    return token;
  }

  private ValidationResult enter(String currentUrl) {
    String urlWithoutToken = Utils.removeNoQToken(currentUrl);
    // redirect if url contain token
    if (!urlWithoutToken.equals(currentUrl)) {
      return new ValidationResult(urlWithoutToken);
    }
    return new ValidationResult(null);
  }

  private ValidationResult redirectToTicketIssuer(String token, String redirectURL) {
    String urlWithoutToken = Utils.removeNoQToken(redirectURL);
    QueryString qs = new QueryString("noq_t", token);
    qs.add("noq_c", clientID);
    qs.add("noq_r", urlWithoutToken);
    return new ValidationResult(ticketIssuer + "?" + qs.getQuery());
  }

  private String generateJWT(String sessionId) {
    Algorithm algorithm = Algorithm.HMAC256(jwtSecret);
    return JWT.create()
            .withClaim("room_id", clientID)
            .withClaim("session_id", sessionId != null ? sessionId : UUID.randomUUID().toString())
            .withClaim("type", "self-sign")
            .sign(algorithm);
  }

  private void debugPrint(String message) {
    if (debug) {
      System.out.println("[RoomQ] " + message);
    }
  }
}
