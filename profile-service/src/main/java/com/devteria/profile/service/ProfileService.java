package com.devteria.profile.service;

import com.devteria.profile.dto.identity.Credential;
import com.devteria.profile.dto.identity.TokenExchangeParam;
import com.devteria.profile.dto.identity.TokenExchangeResponse;
import com.devteria.profile.dto.identity.UserCreationParam;
import com.devteria.profile.dto.request.RegistrationRequest;
import com.devteria.profile.dto.response.ProfileResponse;
import com.devteria.profile.exception.ErrorNormalizer;
import com.devteria.profile.mapper.ProfileMapper;
import com.devteria.profile.repository.IdentityClient;
import com.devteria.profile.repository.ProfileRepository;
import feign.FeignException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class ProfileService {
    ProfileRepository profileRepository;
    ProfileMapper profileMapper;
    IdentityClient identityClient;
    ErrorNormalizer errorNormalizer;

    @Value("${idp.client-id}")
    @NonFinal
    String CLIENT_ID;

    @Value("${idp.client-secret}")
    @NonFinal
    String CLIENT_SECRET;

//    @PreAuthorize("hasAuthority('ADMIN')")
    @PreAuthorize("hasRole('ADMIN')")
    public List<ProfileResponse> getAllProfiles(){
        var authentication = SecurityContextHolder.getContext().getAuthentication();

        var profiles = profileRepository.findAll();
        return profiles.stream().map(profileMapper::toProfileResponse).toList();
    }

    public ProfileResponse register(RegistrationRequest request){
       try {
           // Get Access Token for client (app) from KeyCloak
           TokenExchangeResponse tokenInfo = identityClient.exchangeToken(TokenExchangeParam.builder()
                   .grant_type("client_credentials")
                   .client_id(CLIENT_ID)
                   .client_secret(CLIENT_SECRET)
                   .scope("openid")
                   .build());

           log.info("Token Info: {}", tokenInfo);

           // Create User with access_token in KeyCloak
           var response = identityClient.createUser("Bearer " + tokenInfo.getAccessToken(), UserCreationParam.builder()
                   .username(request.getUsername())
                   .firstName(request.getFirstName())
                   .lastName(request.getLastName())
                   .email(request.getEmail())
                   .enabled(true)
                   .emailVerified(false)
                   .credentials(List.of(Credential.builder()
                           .type("password")
                           .value(request.getPassword())
                           .temporary(false)
                           .build()))
                   .build());

           // Save profile with userId received from KeyCloak
           String userId = extractUserId(response);
           var profile = profileMapper.toProfile(request);
           profile.setUserId(userId);
           profile = profileRepository.save(profile);

           return profileMapper.toProfileResponse(profile);
       } catch (FeignException e) {
           throw errorNormalizer.handlingKeyCloakException(e);
       }
    }

    private String extractUserId(ResponseEntity<?> response){
        String location = response.getHeaders().get("Location").getFirst();
        String[] splitedStr = location.split("/");
        return splitedStr[splitedStr.length - 1];
    }
}
