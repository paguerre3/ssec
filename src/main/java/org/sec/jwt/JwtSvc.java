package org.sec.jwt;

public class JwtSvc {
    // Secret shouldn't be injected in code under production environment, instead is recommended to place it under
    // a secured location like a secret service or storage (Obtained from JwtSecretMakerTest#createSecretKey()):
    private static final String SECRET = "0EC883F6764514CDC5C260EEC01E6BB94034430E0BC99867506EAF77FBFC511A30B7A459030673CE2391EA9973349F4298F4EE99C2DE822D157EB7E52CD112E1";

}


