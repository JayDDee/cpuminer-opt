// Constants from doc/bc3/reference/params-testvecs.
#pragma once
#include "bc3hash-uint.hpp"
namespace bc3 {
namespace detail {
namespace constants {
const std::array<UInt<1>, 8> base = {
    UInt<1>::hex("f70c6462eb2ae2d6"),
    UInt<1>::hex("927cb0e2c353f73e"),
    UInt<1>::hex("bf2f9516fc9c4330"),
    UInt<1>::hex("c15671f266593ff5"),
    UInt<1>::hex("762c297f71890b5e"),
    UInt<1>::hex("108c447e7ebcd488"),
    UInt<1>::hex("c24818761058e50e"),
    UInt<1>::hex("36fd1f3c7fa624b2"),
};
const std::array<UInt<1>, 32> round64 = {
    UInt<1>::hex("80b4847ee1d126d5"),
    UInt<1>::hex("c52a0d9a387a457b"),
    UInt<1>::hex("22e65c431bed21b2"),
    UInt<1>::hex("14667805c6955887"),
    UInt<1>::hex("e17b3ee0aa3cf44e"),
    UInt<1>::hex("d2cd9d698d6a1671"),
    UInt<1>::hex("db425c815c0704fe"),
    UInt<1>::hex("066c4ffd688e12a5"),
    UInt<1>::hex("419215840b275a8c"),
    UInt<1>::hex("369230ade1d36976"),
    UInt<1>::hex("6bab679cb1b90894"),
    UInt<1>::hex("2c1c295d2e646b3b"),
    UInt<1>::hex("3e59f4830d13644d"),
    UInt<1>::hex("1b0031adae0acaf8"),
    UInt<1>::hex("3796b541775d8e24"),
    UInt<1>::hex("2f3efa4806170292"),
    UInt<1>::hex("16075331aa74e4e4"),
    UInt<1>::hex("dae9d5b3ec6cefed"),
    UInt<1>::hex("2820ef5c65f86f0b"),
    UInt<1>::hex("7588f2cff28b3fc5"),
    UInt<1>::hex("a37049d63b598ca5"),
    UInt<1>::hex("3edd8b4d6ca62563"),
    UInt<1>::hex("43e59de592ba46a0"),
    UInt<1>::hex("cf164eec37b7f680"),
    UInt<1>::hex("ffeeebd5c0653331"),
    UInt<1>::hex("ebf298d3d723ccda"),
    UInt<1>::hex("b2c336ac814e438d"),
    UInt<1>::hex("d0a3b74e43a31fb5"),
    UInt<1>::hex("1a6309def1115850"),
    UInt<1>::hex("156d245c87623bed"),
    UInt<1>::hex("81971caeb07b6180"),
    UInt<1>::hex("08cd67e5ce559832"),
};
const std::array<UInt<2>, 16> round128 = {
    UInt<2>::hex("72d2dabbaac34eefb446f99f1909aa84"),
    UInt<2>::hex("d15a623dd1654d61711549a20ca98933"),
    UInt<2>::hex("f80af0b8c6f423c7c2399226e67a0018"),
    UInt<2>::hex("2be1771ab79765a405cc4bf907121fed"),
    UInt<2>::hex("75ddc3d8e0566ca849a987a99529b720"),
    UInt<2>::hex("60826fc8e665ede7a1d91327ebdd2c4d"),
    UInt<2>::hex("af5f60a2275a84b45f7e14cdd2cb98b8"),
    UInt<2>::hex("a28ab2aa854ec5beb6a7e0025fb3c250"),
    UInt<2>::hex("95481fcea93b34219680b307838b4544"),
    UInt<2>::hex("a1d6048ac9f8f6308da650a396026d41"),
    UInt<2>::hex("f9556fbf52a88c1337448d77338dea6b"),
    UInt<2>::hex("ead719a4044d895deba00bae9a3aa372"),
    UInt<2>::hex("e6bc94f7926414a35dc6d29da087752f"),
    UInt<2>::hex("dc248964f9a21c16d9e1d13da4ef534c"),
    UInt<2>::hex("ee3ca1fb0e50d3f5e87b49495b47cfdd"),
    UInt<2>::hex("49b06366a722cff582a524368adf3893"),
};
const std::array<UInt<4>, 16> round256 = {
    UInt<4>::hex("6111f39bfd11b164396410c3827e8d0a305580c292edc12637861eaa70b39a41"),
    UInt<4>::hex("e1490e4bf73d5aea464535d0a21a31db5f0693792b60006b78c70bc875a9669a"),
    UInt<4>::hex("fe00099f5049ad0ed1a5ba1b790d2374d7de1078d67685a5affc74849b7bb962"),
    UInt<4>::hex("d1d70fddb21d577bcf7cd1d6d31f3f079037f4db5550af11ee761ec225206318"),
    UInt<4>::hex("cf0e2c6afd6fadfb96caa96b03cd8242b0fe38675d26281bcd11d4fe89327b8f"),
    UInt<4>::hex("3bdd3a3c74d68e63afe08dc41326e314d282b4ab122fce31df19dafcdd5bb1f0"),
    UInt<4>::hex("351c9afb5cb7987b8a128eccabd57250dfbd4c541ceb948e29675e8674bbc2c4"),
    UInt<4>::hex("0fb1b2ec6b8c8d10a8a181aa42a58c66f0b9328f0ba9cbd4456167a9a6a691ea"),
    UInt<4>::hex("e38b86a71f2ae6d69763d26dcdcab4ff4a29260de0268f7060a6f3adc03159d4"),
    UInt<4>::hex("14be1b97b838aca8c55cb557f99c60d89f8a6e614127b710f83a498bfecffb06"),
    UInt<4>::hex("79c5d2a0e9c9c3d2e89ba2d35ffeada6207b6d170dc53239fb080b788e02f0e1"),
    UInt<4>::hex("40c94e657e14192db7c03690e3234b468f05d8e3a804bc8957b9e4e324f2b1bb"),
    UInt<4>::hex("474cd214da0634afffd351652d7d731649d9fa3b78cd94b81138790ee09cd03b"),
    UInt<4>::hex("900ebe45b91037f8a0445bc6296f9bbc66daf436f0f55fae12e40443ebc81f63"),
    UInt<4>::hex("5aef38a1b25c2be9023e1571bb8d4fa3e839b455dd7b5fd46654e39eedc737e1"),
    UInt<4>::hex("73949255913776de1b80fd175ae409fd459daab2788d2031dbabd97368b8a187"),
};
const std::array<UInt<4>, 64> final = {
    UInt<4>::hex("9955b67ba23081f7cf6ba04a683d7a60d95a85dfc873ac54817083395555c30f"),
    UInt<4>::hex("99784555ee242dfda0a54813a9d3ea9dceef42e7fa66331f4651c0dce4e415c5"),
    UInt<4>::hex("170f26673e7dbb0a84c0636bf6818ffb4e362ea94f962c31baa8ebfecbf90b46"),
    UInt<4>::hex("07aa11fa2a5fcfee178921653f63d8d251f91ea5843f1e8316c48f46b4f733fc"),
    UInt<4>::hex("d735370d48bfdcce3975e3b82d679f5f9a2f60d493f872c93b7176a8440fbb27"),
    UInt<4>::hex("d899501de756bcb135864c083059205e23c8b930c24ab5613e722447a516b4c9"),
    UInt<4>::hex("180e6ad999dd9db2cbbc6a933900dacd71874f942d6eb59fb012027930f5ab63"),
    UInt<4>::hex("dcb0af221294f003e53869e7ce97778f61033b4fe9244710ee639bc6dd332995"),
    UInt<4>::hex("912a7b68f34f6eee00c5c514e05a2f81362deef1f1c0ba8d5906bfd8ad93e48a"),
    UInt<4>::hex("f5befb974f5feb7df8c31b7e33458a4476d17a95f7e7d29a80991ddb2c3b113a"),
    UInt<4>::hex("f1313f1399472a6f5ccdfdfd712c421bc2d35daf57dbcada64ae619444ed9fe8"),
    UInt<4>::hex("68877600cbbaff5052bf81f3a739e3966480fdefa405b9f6c99f669e768f23ea"),
    UInt<4>::hex("673f37f85f3b2f13890645bf615e27c058390731d6a3b913d890bb67328fdf7f"),
    UInt<4>::hex("0650a4eca8b60dacc0772ed24b553f10f39b9e5197060f27eb0e5619f25c48a6"),
    UInt<4>::hex("3731b934e38497146c661d95765377fe3caeb76d0615e5d52a868b7a9f434519"),
    UInt<4>::hex("101d01fe3f98e74b7775842bab918482b3bfef97dccb5bd2771aa47493332e30"),
    UInt<4>::hex("4ae24cc98f987ef675f4d19ee9215fcc59ed4354c04ee809143ac89dfe80eab6"),
    UInt<4>::hex("4c9356eba43c4324498969c35a4b8cc65207cad331ea1de1d89e4848e896d1b6"),
    UInt<4>::hex("bbbdd512ae282ccad19c79d0fa8f32695a1a6eb16dd70d6f80fce2f269aeaef4"),
    UInt<4>::hex("32828e0b7e350cf8b5ebf69f31961744b0a69d436d746990b7005ecd7a1d5c1b"),
    UInt<4>::hex("755820e7ff97314683be5b9af0657182678aeea88c1ed974ec8afde7284bc232"),
    UInt<4>::hex("1c82c1614ebf98ac2abc0943fdb61c4586b1b3ad728fccc270b3978e5901b6a0"),
    UInt<4>::hex("4a30eeef58c74af4bde528cffd3eebb273dd3171e403304fa9c3d061fa3df727"),
    UInt<4>::hex("4ea5259761fe70b5ddc0054536cb2ede56acf773f839b3f5a110a69caf6fb820"),
    UInt<4>::hex("6da17ae5e890f07a827dfbd303eca5f2d51be7f84b164ae337df9a34c054fcf6"),
    UInt<4>::hex("afd1dc3c5ea819070f54ccf511035d2d153585c78ab82ac1e418212ddff2d318"),
    UInt<4>::hex("5590f6b776f76817ef7bf20247c0fc1c93de10ef5eae66c84f7938a15b6374a4"),
    UInt<4>::hex("a1357f946b693c2f5efde95b19694c309344e69a351acc5755dbfe0727d6e5f5"),
    UInt<4>::hex("4e38c422f62b5823a8441df79eb8fbd2b9c2b941aa464b02b437b1cd798dd2f2"),
    UInt<4>::hex("ee939c7637580417240cb209683469b9c349f4c32d679fc5cbb9a8c91faec809"),
    UInt<4>::hex("cd9879979778216e7da34fefe118b158ce919488b37d1627086b80cdfed83435"),
    UInt<4>::hex("7fc58ed8b6f4b34bed803a6996e7dae55a45e98cb3c17adff95c27f9e489a029"),
    UInt<4>::hex("3710e04efbd62c6d4a22305be4a5c246a1eebae3675b0ec6585de1ae6fc3441d"),
    UInt<4>::hex("f1cd05d64625d55f417561bead79891cf55b8de6dcdc7351bd71610480d26760"),
    UInt<4>::hex("273cc20d22bae5446e3cdf7dafbd8ae69ebcbeb575f472e24754d1054703346e"),
    UInt<4>::hex("fb85f5fa5dfcf868eabab1c45a45a615a89ee2553cc127039b9b7fcf81630a72"),
    UInt<4>::hex("76d12280182f5e0093772851d0a7b22b63375462b0df01d585c885725555a6a0"),
    UInt<4>::hex("af0c661b32eb31b44634344f6e8a031d3370cc67f7408465e888e8e8a61c2841"),
    UInt<4>::hex("a7a23205110615751304b17927b2dfcb53e509d0f32aeb553757cdcb26d95c2c"),
    UInt<4>::hex("d387d84911209f0d5be4561a5f229a188b596ca1416854443ecc8f7495140f28"),
    UInt<4>::hex("1563bfdefacc80b131c69fa0540a4aec32b504d96136384d5e66560bf72e1a5f"),
    UInt<4>::hex("e1f77bb83abe2e45ae0070ee2f6afb3a1f805827a347ea9d172c9c5613a717eb"),
    UInt<4>::hex("3f97105dc086f1d11646e12c209284c7e7580352e5c95776fb1fe0f95b210f80"),
    UInt<4>::hex("2db485e568750050b6b2c089f87fa9f6da82b466840704284e1d420a8b183fbd"),
    UInt<4>::hex("405fff4a93c4f70fff3b2fce537e028ab8279822c219eec50ac96805e1e334a7"),
    UInt<4>::hex("a901c8e4585ed7574ffb42e3c3f2099ebdb957c4d7659545661cbe2703641379"),
    UInt<4>::hex("0e5b32c400c04bae0001a0f2e798b51c8e9472e15d4413bd4cabcc116b5d19ad"),
    UInt<4>::hex("26446d2b4cfa5b7b0b556e145fa979a1d0cb3f0ad7eea67d290b6cf63894f77b"),
    UInt<4>::hex("e42fb0dd2e00b32fd0f8c452ed4747afc078c4efc627b530d98e63688809a927"),
    UInt<4>::hex("388b5e4c9933b60072dc31f9827929ac9bf2f9c7a55922245751cc98b1812ebc"),
    UInt<4>::hex("8437e139f1a563acf5a32e8628e3612733abd57d1fccb4f646a96722fc856d15"),
    UInt<4>::hex("5a8ec26dffa90c5d52c82ccd0bfd2dabfe1245392c2940e40f1b47ab2c1bb213"),
    UInt<4>::hex("49a7d025205daca78879172903cf32368ba684b4fc24483f7b2923f08ce3c5ba"),
    UInt<4>::hex("1a689e0246346b2ec3b2ef06d2cdffe332422cc5a16f71acf6e267857aacea89"),
    UInt<4>::hex("eaaab1036f1190119de97718e6cb3629bffaa5e9f9b857f4be82aa7ee027adc1"),
    UInt<4>::hex("4967e0525cf1f05035b4884bc6e3aa8efa3d55e4260034028bc731fe9c5e954b"),
    UInt<4>::hex("60be27cc1bb8fdc10b0d62835ce112a93fe3c4f2723e8938f9651571f3e4df9e"),
    UInt<4>::hex("c3c09a1a2af40fcc2810de3c1cd36bdf0653ae9e3125479ea03d6d8b8b021999"),
    UInt<4>::hex("930873d43406c3991fa26f5be2a4f2580d8c75a7e1196c9ed962e9576c6a2ef1"),
    UInt<4>::hex("e969ccbf6d73649e494f1e91ff17f2f150bcd2d7d6509bc7a21027269105a62e"),
    UInt<4>::hex("ed69c264a65d792056e24a3016f6addf035949c07b738144c3e22109f6a96e98"),
    UInt<4>::hex("f40f828787f7af6bf721cbe37c81042ba45a8e51d4bb911059c6040b58498838"),
    UInt<4>::hex("a85f0ba124516696cf20ee66047fb0844778f53847660432aa75827ad27b2e72"),
    UInt<4>::hex("07725b2a7c500486d866934046e7fe7b87c0dc112fde6941afa82a2ead66dad2"),
};
const UInt<1> E64 = UInt<1>::hex("08cc1751c4763fa1");
const UInt<1> g64 = UInt<1>::hex("7b484f6c1cf497f2");
const UInt<2> E128 = UInt<2>::hex("928a70e905d1724afa5aa27fac6a65b3");
const UInt<2> g128 = UInt<2>::hex("77c60c1d221a0804b223833f64cdffc9");
const UInt<4> E256 = UInt<4>::hex("77f21ca678d771adb27c7c729029c0a72d97ec3a6a936438a30182cddcf6c2a9");
const UInt<4> g256 = UInt<4>::hex("49158f5d1ca2d69cb1f0dd8aee8aa6e21d4342fa7317c71643d782e9b25aae2b");
const U256 H_x = U256::hex("01f2a7758a894831908da9d9fc9974a3c68d19daac88c4f29e376c2727dd1f51");
const U256 H_y = U256::hex("0451ca57637f54107233f2f21a81f7dabc11f967389e16f3e63515bdc148278a");
const U256 J_x = U256::hex("5ef83d753a1c8f8b992bccdf95badacc54886da7a336b8e56c9d0eb3936b3d02");
const U256 J_y = U256::hex("ce9c40d1d51301d7933f6e2d1a12f2c26703e3e3b5feac898ceac5c945d05d5f");
const U256 K_x = U256::hex("304053761b5b7b89577fb84108c5b1a90ed27c06fd39ac546b1be2d29086a7d4");
const U256 K_y = U256::hex("2466a619190c993b840bb99184802f35f5b289ad67aa61cae821f1712c441b58");
const U256 L_x = U256::hex("00830b79c191b3a74e671752e4325abb1a4dfd84ef6e506f967eeae175b44f54");
const U256 L_y = U256::hex("1c79c0c4acfbe7b4adf19e234da0ef8bf5bb0790dc35d7b2dd4ceb9296544e56");
const U256 INVALID_POINT_x = U256::hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
const U256 INVALID_POINT_y = U256::hex("0f63cbbb426c5da1ae3609da2bb48f73cca6988067678d8db0d1596d3e58acfd");
} } } // namespace bc3::detail::constants
