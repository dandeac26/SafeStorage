#include "test_includes.hpp"


/**
 * @brief	In this file you can add unit tests for the functionality.
 *          Only for unit tests here you are free to use c++ and any std library.
 */
namespace SafeStorageUnitTests
{

TEST_MODULE_INITIALIZE(UserActivityTestInit)
{
    // Ensure we cleanup any pre-existing files.
    if (std::filesystem::is_regular_file(".\\users.txt"))
    {
        std::filesystem::remove(".\\users.txt");
    }
    if (std::filesystem::is_directory(".\\users"))
    {
        std::filesystem::remove_all(".\\users");
    }
    
    Assert::IsTrue(NT_SUCCESS(SafeStorageInit()));
};
TEST_MODULE_CLEANUP(UserActivityTestUninit)
{
    SafeStorageDeinit();
};

TEST_CLASS(UserActivityTest)
{
    TEST_METHOD(UserRegisterLoginLogout)
    {
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        const char username[] = "UserA";
        const char password[] = "PassWord1@";

        status = SafeStorageHandleRegister(username,
                                           static_cast<uint16_t>(strlen(username)),
                                           password,
                                           static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        //
        // As per requirements.
        // Registering a user requires the creation of the following:
        //  <current dir>           - %appdir% (application directory)
        //       |- users.txt       (file)
        //       |- users           (directory)
        //           |- UserA       (directory)
        //
        Assert::IsTrue(std::filesystem::is_regular_file(".\\users.txt"));
        Assert::IsTrue(std::filesystem::is_directory(".\\users"));
        Assert::IsTrue(std::filesystem::is_directory(".\\users\\UserA"));

        status = SafeStorageHandleLogin(username,
                                        static_cast<uint16_t>(strlen(username)),
                                        password,
                                        static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SafeStorageHandleLogout();
        Assert::IsTrue(NT_SUCCESS(status));
    };

    TEST_METHOD(FileTransfer)
    {
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        const char username[] = "UserB";
        const char password[] = "PassWord1@";

        const char submissionName[] = "Homework";
        const char submissionFilePath[] = ".\\dummyData";

        // Drop dummy data for transfer test
        {
            std::ofstream transferFileTest(submissionFilePath);
            transferFileTest << "This is a dummy content";
        }

        status = SafeStorageHandleRegister(username,
                                           static_cast<uint16_t>(strlen(username)),
                                           password,
                                           static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SafeStorageHandleLogin(username,
                                        static_cast<uint16_t>(strlen(username)),
                                        password,
                                        static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SafeStorageHandleStore(submissionName,
                                        static_cast<uint16_t>(strlen(submissionName)),
                                        submissionFilePath,
                                        static_cast<uint16_t>(strlen(submissionFilePath)));
        Assert::IsTrue(NT_SUCCESS(status));

        //
        // As per requirements; a file called "Homework"
        // must be created under the users directory.
        //
        // The file must have the same content as the copied file.
        //
        Assert::IsTrue(std::filesystem::is_regular_file(".\\users\\UserB\\Homework"));
        Assert::IsTrue(std::filesystem::file_size(submissionFilePath) ==
                       std::filesystem::file_size(".\\users\\UserB\\Homework"));
        status = SafeStorageHandleRetrieve(submissionName,
                                           static_cast<uint16_t>(strlen(submissionName)),
                                           submissionFilePath,
                                           static_cast<uint16_t>(strlen(submissionFilePath)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SafeStorageHandleLogout();
        Assert::IsTrue(NT_SUCCESS(status));
    };
};
};