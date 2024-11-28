#include "Utils.h"

int IsSpecialCharacter(char ch) 
{
    const char* specialChars = "!@#$%^&";
    return strchr(specialChars, ch) != NULL;
}


int SanitizedUsername(const char* username, uint16_t length) 
{
    
    if (length < 5 || length > 10) 
    {
        return false;
    }

    for (uint16_t i = 0; i < length; i++) 
    {
        if (!isalpha((unsigned char)username[i])) {
            return false;
        }
    }

    return true;
}


int SanitizedPassword(const char* password, uint16_t length) 
{
    if (length < 5 || length > 25) 
    {
        return false;
    }

    int hasDigit = false;
    int hasLower = false;
    int hasUpper = false;
    int hasSpecial = false;

    for (uint16_t i = 0; i < length; i++) 
    {
        char ch = password[i];
        if (isdigit((unsigned char)ch)) 
        {
            hasDigit = true;
        }
        else if (islower((unsigned char)ch)) 
        {
            hasLower = true;
        }
        else if (isupper((unsigned char)ch)) 
        {
            hasUpper = true;
        }
        else if (IsSpecialCharacter(ch)) 
        {
            hasSpecial = true;
        }
        else 
        {
            return false;
        }
    }

    return hasDigit && hasLower && hasUpper && hasSpecial;
}


int SanitizeFilePath(const char* filepath, uint16_t length, LPCSTR appdir)
{
    if (length == 0 || filepath == NULL) 
    {
        return false;
    }


    char normalizedPath[MAX_PATH] = { 0 };
    char resolvedBasePath[MAX_PATH] = { 0 };
    

    // Normalization strategy
    if (GetFullPathNameA(filepath, MAX_PATH, normalizedPath, NULL) == 0) 
    {
        return false;
    }

   
    if (GetFullPathNameA(appdir, MAX_PATH, resolvedBasePath, NULL) == 0)
    {
        return false;
    }

   
    if (strncmp(normalizedPath, resolvedBasePath, strlen(resolvedBasePath)) != 0) 
    { 
        return false;
    }

    
    for (uint16_t i = 0; i < length; i++) 
    {
        if (filepath[i] == '\0')
        {
            return false;
        }
        if (i < length-1 && filepath[i] == '.' && filepath[i + 1] == '.')
        {
            return false;
        }
    }

    
    return true;
}


DWORD EncryptPassword(const BYTE* password, DWORD length, char* hash, DWORD* hashlen)
{
    DWORD dwStatus = 0;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";
   

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        return dwStatus;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        dwStatus = GetLastError();
        printf("CryptCreateHash failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        return dwStatus;
    }


    if (!CryptHashData(hHash, password, length, 0))
    {
        dwStatus = GetLastError();
        printf("CryptHashData failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        return dwStatus;
    }
    

    cbHash = MD5LEN;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        DWORD j = 0;
        for (DWORD i = 0; i < cbHash; i++)
        {
            hash[j++] = rgbDigits[rgbHash[i] >> 4];
            hash[j++] = rgbDigits[rgbHash[i] & 0xf];
        }
        hash[j] = '\0';  // Null-terminate the string
        *hashlen = j+1;
    }
    else
    {
        *hashlen = 0;
        hash = NULL;
        dwStatus = GetLastError();
        printf("CryptGetHashParam failed: %d\n", dwStatus);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return dwStatus;
}


DWORD VerifyPassword(const BYTE* password, DWORD length, char* hash, DWORD hashlen) 
{
    printf("Given hash : %s\n", hash);
    if (password == NULL || hash == NULL || hashlen != (MD5LEN * 2 ))
    {
        // Invalid parameters
        return false;
    }

    /// obtain hash of password
    char generatedHash[MD5LEN * 2 + 1];  
    DWORD generatedHashlen = sizeof(hash);
    if (EncryptPassword(password, length, generatedHash, &generatedHashlen) != 0) {
        return false;
    }
    printf("Generated hash : %s\nGiven hash : %s\n", generatedHash, hash);
    if (strncmp(generatedHash, hash, hashlen) == 0)
    {
       return true;  // Passwords match
    }
    
    return false;
}