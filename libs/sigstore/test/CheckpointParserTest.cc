#include <gtest/gtest.h>
#include "CheckpointParser.hh"
#include <sigstore_rekor.pb.h>

using namespace unfold::sigstore;

class CheckpointParserTest : public ::testing::Test
{
protected:
  CheckpointParser parser;
};

TEST_F(CheckpointParserTest, ParseValidCheckpointString)
{
  std::string checkpoint_data = R"(rekor.sigstore.dev — 1742
10756292
RBQ8BNcz7Mv/QCKheLsDJTYNGn9i1Wq4KJwFrKZOKT8=
Extension line 1
Extension line 2

— rekor.sigstore.dev wNI9ajBFAiEA8wVPLXCwWXfpG8=
— another_signer fDsAWCqW+xZgp7Q4zIgONE=)";

  auto result = parser.parse_from_string(checkpoint_data);
  ASSERT_TRUE(result);

  const auto &checkpoint = result.value();
  EXPECT_EQ(checkpoint.origin, "rekor.sigstore.dev — 1742");
  EXPECT_EQ(checkpoint.tree_size, 10756292);
  EXPECT_EQ(checkpoint.root_hash, "RBQ8BNcz7Mv/QCKheLsDJTYNGn9i1Wq4KJwFrKZOKT8=");
  EXPECT_EQ(checkpoint.extensions.size(), 2);
  EXPECT_EQ(checkpoint.signatures.size(), 2);
}

TEST_F(CheckpointParserTest, ParseMinimalCheckpoint)
{
  std::string checkpoint_data = R"(test.log — 42
1337
abcd1234

— test.log someSignature123)";

  auto result = parser.parse_from_string(checkpoint_data);
  ASSERT_TRUE(result);

  const auto &checkpoint = result.value();
  EXPECT_EQ(checkpoint.origin, "test.log — 42");
  EXPECT_EQ(checkpoint.tree_size, 1337);
  EXPECT_EQ(checkpoint.root_hash, "abcd1234");
  EXPECT_TRUE(checkpoint.extensions.empty());
  EXPECT_EQ(checkpoint.signatures.size(), 1);
}

TEST_F(CheckpointParserTest, ParseFromProtobuf)
{
  dev::sigstore::rekor::v1::Checkpoint protobuf_checkpoint;
  protobuf_checkpoint.set_envelope(R"(test.log — 42
1337
abcd1234

— test.log someSignature123)");

  auto result = parser.parse_from_protobuf(protobuf_checkpoint);
  ASSERT_TRUE(result);

  const auto &checkpoint = result.value();
  EXPECT_EQ(checkpoint.origin, "test.log — 42");
  EXPECT_EQ(checkpoint.tree_size, 1337);
  EXPECT_EQ(checkpoint.signatures.size(), 1);
}

TEST_F(CheckpointParserTest, ParseInvalidFormat_NoSeparator)
{
  std::string checkpoint_data = R"(test.log — 42
1337
abcd1234
— test.log someSignature123)";

  auto result = parser.parse_from_string(checkpoint_data);
  ASSERT_FALSE(result);
}

TEST_F(CheckpointParserTest, ParseInvalidFormat_TooFewLines)
{
  std::string checkpoint_data = R"(test.log — 42
1337

— test.log someSignature123)";

  auto result = parser.parse_from_string(checkpoint_data);
  ASSERT_FALSE(result);
}
