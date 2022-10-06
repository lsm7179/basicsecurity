스프링 시큐리티 스터디 레포입니다.

## 인증 개념 이해 - Authentication.java

당신이 누구인지 증명하는 것   
인증 후 최종 인증 결과를 담고 SecurityContext에 저장되어 전역적으로 참조가 가능하다.   
`SecurityContextHolder.getContext().getAuthentication()` 로 꺼낼수 잇다.