#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../include/SHA.hpp"
#include "../include/SHA1.hpp"

class SHA1Test : public ::testing::Test {
    protected:
        void SetUp() override {
            sha1 = std::make_unique<MyCryptoLibrary::SHA1>();  // Shared setup
        }
    
        void TearDown() override {
            // Cleanup (if needed)
        }
    
        std::unique_ptr<MyCryptoLibrary::SHA> sha1;
        std::string test_input;
        std::vector<unsigned char> input, expectedHash, hash;
    };


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
    
TEST_F(SHA1Test, HashCorrectness) {
    test_input = "This is a test!";
    input.insert(input.end(), test_input.begin(), test_input.end());
    auto hash = sha1->hash(input);
    
    // Example expected output (change as needed)
    std::vector<unsigned char> expected = {
        0x8B, 0x6C, 0xCB, 0x43, 0xDC, 0xA2, 0x04, 0x0C, 
        0x3C, 0xFB, 0xCD, 0x7B, 0xFF, 0xF0, 0xB3, 0x87, 
        0xD4, 0x53, 0x8C, 0x33
    };
    const std::size_t expected_size = expected.size();
    ASSERT_EQ(hash.size(), 20);
    for(std::size_t i = 0; i < expected_size; ++i) {
        ASSERT_EQ(hash[i], expected[i]);
    }
}
