#include "includes.h"
#include "Commands.h"


/*
 * @brief       You must not modify this file or this project (SafeStorage).
 *              All changes made to this file should only be for testing that you have fixed all vulnerabilities.
 *
 *              Your main responsibility will be to implement the missing functionality in SafeStorageLib.
 *              All new files will be created in the SafeStorageLib project.
 *
 *              In this file, you must identify all vulnerabilities.
 *              A file named "vulnerabilities.txt" will be delivered alongside the project.
 *              The file will list the identified vulnerabilities, the line(s) where they are found, their impact, and how to fix them.
 *
 * @note        For bonus points, you can use SAL: https://learn.microsoft.com/en-us/cpp/code-quality/understanding-sal?view=msvc-170
 *              To run SAL: right-click on the entire solution Solution 'SafeStorage' (2 of 2 projects),
 *                          go to "Analyze and Code Cleanup",
 *                          and select "Run Code Analysis on Solution."
 *              You can add SAL annotations to all functions (both existing ones and those you will create).
 */


static void
PrintHelp()
{
    printf("Available commands:\r\n");
    printf("\t> register <username> <password>\r\n");
    printf("\t> login <username> <password>\r\n");
    printf("\t> logout\r\n");
    printf("\t> store <source file path> <submission name>\r\n");
    printf("\t> retrieve <submission name> <destination file path>\r\n");
    printf("\t> exit\r\n");
}

int CDECL
main()
{
    char command[10];
    char arg1[MAX_PATH];
    char arg2[MAX_PATH];

    NTSTATUS status = SafeStorageInit();
    if (!NT_SUCCESS(status))
    {
        printf("SafeStorageInit failed with status 0x%x \r\n", status);
        return -1;
    }

    PrintHelp();
    do
    {
        printf("Enter your command: \r\n");
        scanf("%s", command);

        if (memcmp(command, "register", sizeof("register")) == 0)
        {
            scanf("%s", arg1);    // username
            scanf("%s", arg2);    // password

            printf("register with username [%s] password [%s] \r\n", arg1, arg2);
            SafeStorageHandleRegister(arg1, (uint16_t)strlen(arg1), arg2, (uint16_t)strlen(arg2));
        }
        else if (memcmp(command, "login", sizeof("login")) == 0)
        {
            scanf("%s", arg1);    // username
            scanf("%s", arg2);    // password

            printf("login with username [%s] password [%s] \r\n", arg1, arg2);
            SafeStorageHandleLogin(arg1, (uint16_t)strlen(arg1), arg2, (uint16_t)strlen(arg2));
        }
        else if (memcmp(command, "logout", sizeof("logout")) == 0)
        {
            printf("logout \r\n");
            SafeStorageHandleLogout();
        }
        else if (memcmp(command, "store", sizeof("store")) == 0)
        {
            scanf("%s", arg1);    // source file path
            scanf("%s", arg2);    // submission name

            printf("store with source file path [%s] submission name [%s] \r\n", arg1, arg2);
            SafeStorageHandleStore(arg2, (uint16_t)strlen(arg2), arg1, (uint16_t)strlen(arg1));
        }
        else if (memcmp(command, "retrieve", sizeof("retrieve")) == 0)
        {
            scanf("%s", arg1);    // submission name 
            scanf("%s", arg2);    // destination file path

            printf("retrieve with submission name [%s] destination file path [%s] \r\n", arg1, arg2);
            SafeStorageHandleRetrieve(arg1, (uint16_t)strlen(arg1), arg2, (uint16_t)strlen(arg2));
        }
        else if (memcmp(command, "exit", sizeof("exit")) == 0)
        {
            printf("Bye Bye! \r\n");
            break;
        }
        else
        {
            printf("Unknown command. Try again! \r\n");
        }
    } while (TRUE);

    SafeStorageDeinit();
    return 0;
}