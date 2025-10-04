#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../include/MessageExtractionFacility.hpp"
#include "../include/SessionData.hpp"

class SessionDataTest : public ::testing::Test {
protected:
  // cppcheck-suppress unusedFunction
  void SetUp() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
  }

  // cppcheck-suppress unusedFunction
  void TearDown() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    // Cleanup (if needed)
  }

  const std::map<unsigned int, SrpParametersLoader::SrpParameters>
      _srpParametersMap{SrpParametersLoader::loadSrpParameters(
          MyCryptoLibrary::SecureRemotePassword::
              getSrpParametersFilenameLocation())};
  const std::map<unsigned int, MessageExtractionFacility::UniqueBIGNUM> _kMap{
      MyCryptoLibrary::SecureRemotePassword::calculateKMultiplierParameters()};
  const std::string _A_Hex{
      "F6FDBCA9750B211E9A12DE1D60E54C7942C65D1D30826E552824E10A0777FEA1"
      "B38EE8CE5F2AC5D3BE76886D3F630EF44584382E8C303D8249420D08586B52F0"
      "81D10B0D9C4187D9CE7153E5E3190B309E7255296BDD9E4166A515C48848BF6A"
      "0F18C8C711D75429628D0A209FC603A808683D526B651F0C43F82268C203F054"
      "3ED36219F7B4534F445B7025DB6799E8EA3290682EC59DB2872EC9455BCA3B31"
      "B6EF6C552E7CBC384270A87383AB60CA99CD72889E0F64B00DD01E00E4F4192A"
      "6DBCB55ADF0C2523F177F964B4DA78AA5D022BCDEF265888C446730B19CED207"
      "3C7123FE53FF0893A486C01B4B9B1433F7A8A7689C1A4A7E99AF13B4A9248523"
      "B815BAD5D14BC94C7A05114540D9F75DCDA5BB468BF2D2FDE33D5D6634BDA360"
      "69A7CA3690BBEF1CC5BF22D41A9A9785EA962BE8C2933E07B53709C1D58D1E48"
      "6B472BEF3F8FA4722AC5B64AB49823A9BD1076C9DC7979E62EA3C230586E2A97"
      "D163CC2E000C9F54E1F43AAB8DBB1C54768DFA9E3553D94EE76107969E992325"};
  const std::string _B_Hex{
      "F4D69379248D20EED58A337FB5E470B6C3ED3E3020DC88E51FED0DADA1FBAB41"
      "FD5A2E5502E2EC15373D069C309797747F08F1E7AD6453C42BF4858FFEE011AC"
      "1D09DF733B38C0D506B56D4EC8854D1DA15B69A40CB3CD6E12D90C6558C20CE2"
      "C4DB41E271008AE344FEE14BE3B33734D1D09EEEC40FE34DB81E462D608FBFBB"
      "E833EFDFACE5D7BA10DB46EAB4CFF490A99A8D65EAA4214746793286F29EE728"
      "9D7DD61B6DBD499088D80914A8E2ECD1257863C8F5821854605D1D723304DA25"
      "6F66C33CF4A87FE87A27E9CAC7B6A74CE6381587DDAB37FD3B8B70CE8B191B66"
      "F4ED27C8356CD02C6DC269C0651DB09EE07CE22064002DD624AFADAFF5393AC0"
      "422FABE39B1928B0B299B35311FDB46EE35C7E9FAC2467469A61705275B06D36"
      "FC588007F077B674126A56228C7B836271531293FBAE7FAA9F08E852F67C65EA"
      "2C598A9D7090BA64FE89A3364F87FE7B27BBED1862A01A42A348CD64AFEE58CC"
      "CA02B0764B813608C0A98DC9F815294D26746DF7DC28B79C6EABF08017406C06"};
  const std::string _BHex{
      "2CCC8822FA0BDF170F4604F739AAC5C2952DE8A5EA1017F43AE492DA3CE416"
      "BC5ACC45AFB28C8A634412CE37549BF9035C952850837E023B8C0844BF4D4B"
      "E233D6194A54C8972864055466F31B61BE6F0DDBCF6319CB50965E24063DCE"
      "77FD63C6568775F8DDCA7F1206AD4848CD77188343AC57727CD68C281E5516"
      "9AD9320CF2262C6F2A9F22E8C01C4D87BFCE81FDF21E9E0425CDC842FF037B"
      "575B123C597582C03F10D9CE9201AC14122648ED46991DEA46A81EDE6092DE"
      "E42CE45CD92709D08EFF75CAFCC91C8FB5CC9CF57BDDB4F9C51F08C771B946"
      "6EE8287C4AA2373706E8A9B389F012BC4DAA4D4A018EF07489095F266F2FCC"
      "A643B5E215C693F7ACED97D4501D9E0F71163002C66AC55EEAC7F6B79FBDB3"
      "8869F66F98C9003559BBC2D8905CE62B9851193D5F3142B36573066A155181"
      "0507E4420011F1455D886DD62B70D1C582C41F6B0A052F8095682E66A11974"
      "CCEA240005B7479F84FB5053022DECEFBCF11D65F5767FC3640D9DF0F7BEB3"
      "681C6EBB5C95A1E539809217C8BBA83330F11F9F3D848973C4B933E2E6FA4C"
      "2110714E50B6F00E621F51BDD3E412C2408CD81BFF798E4092FCD55BE2C04A"
      "87D8F4FB1203A588668777B0BE63DF0A01E9753FD512192941473939543941"
      "39BD783DFA7F915FC881DDB5C52F53CAD601EF1DEB141E81E39B4EFC3AE84F"
      "1C064A08FC057A795C6475C374790B2DD935E228726C7C49E818CB017E1351"
      "F94FC04813074EB2D7E4425B407161997A8BC60245881BBD7FE96914676ED6"
      "2AC08DD2CE09C2C3DA2A702F4F28B76E853D5FA742D240BCEF8EA109E14DF4"
      "FA8E473110CFABB0D0D7E8353AB940BEA35BA53A8D87F0688F5018D4B0193B"
      "EC4D88A31E6DFDFD68130B91A00133ACA11DD06AD2597C522D9D3F8848E818"
      "892E99D1E8A765C8697015FDF5AFE7BFD236F1013EF570A4C9C692357BF9E0"
      "37D7E85DDA709FB2210AE7563FCBEF650238395F29CC84D1C4D69A2ED8F2D5"
      "58EFA579E021C04EB5717E0C451181C0F922D6F66767F2FEA9AE3BC53B7C89"
      "37203314D31BC281F4E7389A808BB3CBF503F22F07E4382819071FC743C51F"
      "98DCD307C7EC2BF85183FD0EC9CBC51D316855017CA5BCECCF29775AC22A49"
      "35B9B26D5843D049AA1DB8A20D0B51BE0DB73AC416DE60A71B586688055A82"
      "3A7834B5B7C38859116979BBC71817E1559824274AB48FF7EAAB0748B8C724"
      "3910E7AF147CBECB8448729321A7AFB9FCD195B4D0CBF103250961A8CB6FD1"
      "9AA5A3063E462FD95835B7178886C08CC4DCF8F0AC111535E3E59FD7314A99"
      "E809718E24479FCA7F037C96A3976936BD4EB9801D99DD2BFDBD3E750223D7"
      "71672ADDD6BE6B208610C86127632FE89C936214C17934244BA95F23B572BE"
      "A0CA149185D39AB180F7EC871653BD8108BEF9219928B3B07A6C9E7233DA02"
      "22"};
  const std::string _xHex{
      "121F773DEE392FF993A08983C3818EA4B9EA5599607E2745C35CB145A9A581"
      "FDF59D663345EAD48EC3D96B85BDE691DC46FB4E62446F0C52B5120D2FFBD7"
      "C340"}; // Private key parameter x (hex)
  const std::string _aHex{
      "ADEBD662C22FA9628A187C02BCB9A0BD84A3B7719D5993F7022C273218F0EF"
      "737E937FFB3D4166D096AB8B424BB0ECE76FA698761DA7BB4C4BCE9DD95B93"
      "3E43862249ED3A6D8D6CAC6A8357E0A75665DE247C414B0DFEDD158FD216F0"
      "3DADB6EC15D0F2E7159E34607BF729DF6164970964F01DEDDADA3CAFEC6580"
      "89F8C2D4CD253B33272876EE0778D472B8260CAF9B7DEC46B2C333AEEDA7EF"
      "2160FDE31D052B41A3255F2B9457300DEAC0DAECDB0B406E4C352DFFC46345"
      "E86665ECB22F100E5EB812F9A11B2B0953B09F68B06EBFC937BABD38DC8F26"
      "4E94C56A1D2A8781BF3DBA36C7E4F4CC626958BABBF4490321F6B39A0A6178"
      "F09325077763DBD2D379C9300D58FB22436A9E1D7462BE8E71C6B78001385C"
      "E8665037D8EAB7AC1F67B5C91C22CF87980125A8D033A69EBFAE9E70255498"
      "B9ACB49BED258108349BEDA81158CDF95732C3124B278D8B71FE7743D60CEC"
      "5AFC3A115BF98793694D09D7D6860436B5483AF4FB95E8D6CAC4059F71244C"
      "13939452F70932E6EA2DE661B0F09E20E788771308B51F69CAF1A89069C3E9"
      "411B36F6213C71FB2ABE309648D4E204EE9FED6A9642ABF291BC01A48E1A17"
      "8D5A61114513D22FBA869AFC125BBA7C50A96D7DEA59F0AC6A5A0AA0C602CB"
      "D00619EBBF57CB1FB001B782066D0789C177944ED9E7A1DC545B03FE75BB81"
      "150A0FCC96A5BA3726B40C2E0544F58B3BD29733A9F2AD37B0EDAF2F5E64E2"
      "F5CCC329AF752DBAD2EB0EFB51344D6A621AD5DF6A3B4BA8AFCE673A9D559D"
      "1F3C35D4BF51D33FE91337F881A4CCAE23E7A0B2649E82BB87B6FF87638CD4"
      "58761C9B2F806DA8FCA035846CD43468C45C9CA0B340523F22985A46F98979"
      "0371C8B398498BA1CBD546EA29DA9BD55E9E9EB03679985A3A3557CF33FC7D"
      "28DA42816457A2548757391A8728DA277266FD34BB0220B373C92E9E743C77"
      "3DC2157BB98934E8A030E700337B4FE88BDE49DBB9BC409B44D79B4F616127"
      "3EC757CEABDFF2CA58107126706E1F32E970F802F47EF11A7886F4DCB25F34"
      "4405B76972872D001F6A79F20934D278FFCDAA73C46D9A3D76360BDF879F34"
      "256CE95C1A33065092B4F4DB76DF1738B8A3E5373F4D407E3466D93410F59F"
      "8ED6B607756FA5C892075154F3276774B48D03DEB37B50C5BA108AD5943525"
      "BA07BECF7A05BC220C8D4FF376D9F82BF1E61BAE5F849BE0A931237F90733C"
      "B7A193C9AD40FAA9D2073D082E19B7CFBDA89FB09EC334A15BED51DAF197BB"
      "0A13C6F7105C499C7225E263257FB4E6E4346E03D94B86FFB206574E75BB8B"
      "D81988E034CFAEAE15754FA8136E04FCD9B77A948B477A70D6548C61D29DE0"
      "810B8D62D554DD6B87FBBE40D62FBDD24D0B94030BC629B647D2A93F99B090"
      "7344399049E3AF6406AAAEB057D23F3C24A5FC6CD3D8CC21A2CCA6FBA6EE58"
      "B9"}; // Client private ephemeral a (hex)
  const std::string _bHex{
      "9CB52A1B2C3E796FA127EB79236B7141618AEBB9313ED7E35502B7DF63123C"
      "64FB935E4160F89DE3748254A045EF5F69305619A21C7E7ECC82A55BA8DBA6"
      "683F8F457CB600FD21EF6AB53ED14C35AF00C62CA77B0BDFFC115D13174821"
      "3577BE2D58712A4FED86837859AD124167D3BE3578FE1BAAFAEDE0AEB96E88"
      "8C6536CA32377BACDDEB3B52F593EB4D43D6313AECBEDE807C68B185869307"
      "BDFB0B775DC738503BFA7CFCB7D93C2894EBB2312EA6B6A3D45AA7B6F829EA"
      "D2AFFA1629C30D9CF65E48DA43A261449822818AA80324C8D37BCD7F94C590"
      "278CF5D926E01F635F46283A6A2257862024D86F8F0518128C766DBFC3F77F"
      "D6BEEF73A7F08CF5B7A142CFBB9FC3B40D820403F42C3001330F2D74353C13"
      "A631C7D219F18C9F8A3C923447A7A5A87D40564A2E8ACEDC69122BFC08D594"
      "C3CB808B9F761EB2567AA4306AA028C71353CCD9C0D292D54BAE912DFB5490"
      "9EB6772D0FB6B1BB8F7E292949B01249149856509DF80C827F1057867CBEDD"
      "065AD8B5FB3FDD9A11A5823EACBF8728CA436A9ECCB9FC88A33434CCE836C6"
      "292323D3CBA33E8BCD0AA5E907B64F1649A0A35E3EC4BAB99D8EA91568C68C"
      "FE8D5A2CD443D8D58D9715CE002A4575C46BAC735A3846ADD2E6CDDAFEFAC8"
      "799A2E339F6FAAA576D1D305C460F9C19D328348067BAEE89A1C6AF6E1D1A5"
      "42D1FBA1E982924D7E4F5257B59156D210F62C623F34BD6B3BC4D31BAE16FF"
      "E19AEF9E906A0B27CD9F908743C78207F5540AAA50DD69B5996A3B8CB57EDB"
      "255719853682E69D8E004DCE5789875DDF8F46A217B8BC6BCDCDC8A98C0491"
      "EB61E1565AA42BFD0DA7CAB35CF3128B61FB820C5321E759EC25C94DBAFE25"
      "09CEB605CC300A19E521DBF2F461B46FDF799B09332D10FB67E3ADC34E0D69"
      "6162F6D0E4BED14480B7A9C555697D86F649D02747278634B6F9EFEEF4B9DA"
      "D7358E68769A8A102085AFE43DF353CB8058B5B6269AED9B39A9105826A59B"
      "3254BC234D416C4917AF0FFACE256E093D4996120E794AC413D36A35FA2E52"
      "F9D8935CC173F70719C5C4072D321946508617A22323581C3170B23FA004E3"
      "465B831BE258C78EDE1C6BC5ADC84FA7ADFD2748E57B86D7B2269036CD07FB"
      "37340B16EB1C47209E7F6BCBF624BFFE81FA586C5BA8C95D7E5B2C8CC64B39"
      "3A9D743B3D05FB5A617E2E209870D852978FA5CBE17836E9C144490418A152"
      "DD72BA5318B48D7D817DEA3794F3013612C25315E7E60774E5305CECDF49B6"
      "D0BFB84572ABB355BF7453ABB30D4D2B3A48041587FEB7BBB983CEF9F8D79C"
      "587DA7A1A594FD8DD6F4013BFA6870BA07AC8FA177B54BAF1FCFB83273DF4C"
      "043670AADE717841C7A95C87BCBF8F554E9F2E81053290ED57F329611C7274"
      "E80DEFA13EE52B39D5705B4BD9B7C8DF3D40CBE48C03AD452617F0F5CDD028"
      "CA" // Server private ephemeral b (hex)
  };
  const std::string _uHex{
      "121F773DEE392FF993A08983C3818EA4B9EA5599607E2745C35CB145A9A581"
      "FDF59D663345EAD48EC3D96B85BDE691DC46FB4E62446F0C52B5120D2FFBD7"
      "C340"}; // Scrambling parameter u (hex)
  const std::string _SHex{
      "6C6B5A37B694B4D1102ABAB6DEEBBB8A4E20145322CF216B93E253AAE7A31EE6"
      "FD1479DED9F72B111289CD724221EAE2B05338C397EF942ACA4E24AD698825EF"
      "BBE6C7CB9D98D2EF21FC4A25FE3921174FD20892267B46FC5F1EAC06C65AB938"
      "BE0B1B30334C50C66B9E280482838E6E3A6BF7908F863E2598E5C256C0277640"
      "90C5B41F21038D6D92540A1C5AE61D87880A3CF60796EF64BE53AE8641B1FC6C"
      "1DB6DF153D1488DCB962C212E225C5A5F682EEFFD179BAAA62832AD2595DA9CA"
      "B76C987CB39AD9824E734B8675F49A5DB5C81B132195AF57EFBDF1CD4E314F04"
      "EB63D2E71863D07BA544B55BBA6A29CC7EDB1524999CF7389F5828FAF231A9F7"
      "0E7E46DEC651D1B33526AD448934A0E26FF2183FBF01320B5662A3A8102C0A47"
      "EC20DC8A7B25DBB6A36FFFE7E7F3C626ADCF088DD38C896B1604252EBDBB7F54"
      "E92053E9DF9CE9684CBBEA03EACD64848790A1C4E5E4903665200F4546D3B5C1"
      "F7397DC7B285340DBB0D9C5F27446F13216EF01152B098CEB299A5BE3C09F49F"
      "4F9D031964C44A2F33B1C7D69989406A9D254A999D26F7707BB9BAD1CFEBC879"
      "CD100665DBEB75C3AE9A0AF75E3A822DC8C67FF99569205006C24579EC5B0EBC"
      "6F03D2BD8DAEE6DD351A8826C7115131D1C62D17847FC193F4BD37AF31E46DCB"
      "161A9ED6EEFD61D0CB256B574755D61A3CDCEC1AA17E0030C0A1F0C6219EF1BC"
      "5D8707B9C40F82FDDB3C5236DE37FE368B23337D4516459B18988A5F70214C70"
      "B8C8C9344F4B77C60DCA4A7C3AB0141A8BCC7A79E3873589A64E08631A9FDFE8"
      "33C1D4674D0EA32519CE9DE47944EAE4BDC4EB7D72F71E95A4E6ED5B2EA2B21A"
      "EE380B9A253359C4DA8E3F44FD36683030465C0DDBD3E598573BCFF1969F6834"
      "E1757EF3C5B355FD379A8D3472A98E2672A34AA57E0CB804334EFCB283DF06CA"
      "8987D9E57A5793A794355DA676B4007A806E0F79D8A0629032169C8BD74BF364"
      "159E7E195D0369AE44C4499F223B6D87E56B18F79DAD9E406B8BC13C1EBED3EF"
      "BAC8CC389872C61C84D051393B53DBBF56ECD1D594C31FD2FE4F668376A57DAE"
      "016062CE1E1685A3B4AAB3D04A8E96F3696B6BA8AE8E1BFD3BF52E0E208DB31E"
      "71081A4B8127F10A93B0145B5500F3345373AF1678853A93D6EDEE05931B0239"
      "2551FA390DDFFDE77D11149FA29708E43437BE81D6ABB1364058DBB3C7C96946"
      "C741F7B42DFE85E79D3FBC86ED16E27206D574BF003F128A9530CB7F0FC3AC55"
      "AA137EFCE697B23A613F9AB6BCD31D54F5B5CF64E72089E1A4DB4DD503B96EEF"
      "104D5D50C140D510A955DE28FC97DF89A6B788A58046063BA9F9B7309C95DB60"
      "B0BC86421ADD1B822D4D907646B6DE637034FBDC652143A620049010D3966803"
      "3575CCC392600D7F2059C6E1356C655C17281ECCF4AC7253AD45C750CDCD902F"};
  const std::string _username{"Bob"};
  const std::string _saltHex{
      "4118F5DFB7D944C02FAEDBED7982BF5505BF4B681A14EA54C5D2F2471BC2C793"
      "CE74D80D8D889A85E34BD536355A3E059AC9C34331D83FC16C757C214D99246A"};
  const std::string _KHex{
      "39FDCEC9D0DC0BD723318C18F55951C3BB9B442FDE6452AA5BAC2B8F6A2B61BF"
      "406C79A849C324AA0B3DD7854FB5C56763E305889689E04C8E83A95E244410E7"};
  const std::string _vHex{
      "1568E0B0AE00EA52EB8FE8442E1410AB59F17507D3C41B77E3CA36646CD9090D"
      "AEA70CC690BE9DD640FCE59C70DE913AFE98B68F6B116F28972EBF46C5C31DD0"
      "70A438DB0A0F68CBF66A3B41EA29B14891F4F58FC7A0BD75C2FA240DA70363B4"
      "4858B1531D05352BD1DFFB783C7F57D4720BD571FBB2D5C44A36A653A5B83F00"
      "98ECCDC8A22D9499EA1F4D114DDF4405F328BA816413D49136CB7D9919C36658"
      "94BD7603B9F1B5A9A66FFDCE170B39CA7F785E5002F39DFD949463393760B472"
      "96D229E9B3FBF49DFE2CB2915B25F9CEFDFCF3F97A25C24C5E33FBEE6C8F5C13"
      "56EE491549C91E932FDD7DDA4C68C2F7B3D637C798A89674C634973321567CB9"
      "C3D137F28109B5020E2588E08ABE0B38FD488FB8CB1A67E24C2CC6D3DEDC8FC4"
      "650DF9DDB296D6FE8E6366E387CF5F7B12D71DDD5E4337F90044006F2AB61C0B"
      "3BB02053E7365CC9E4F013EE6A44E9FC47B46E94DC7A4DE30A43D3D1BC395233"
      "58FD79F43B7C500ACD3A0F9908879909EB3AD25A36A66FF800297D6CC1159448"
      "909369E4FCDE5C83EA78AD17E31F96901DAE523230816E22E151ED1BEC6206BA"
      "3B2A475414694086342C434A10654EB6285D66B393E2D8C185BF667E2CE1726D"
      "49A61EEFCE89F23E6F37682002B056D55839FA0C1BF7A399878FC7CD6F9D5C3A"
      "7AFF2C4D709E90DBA3A562997F75593DA5EE0223362D5AD17CB8B45AD7D5D3F6"
      "D619DB80A1DBAC894AA4AE8D7E72D2B17F64BA3DCBC224229ED8AA8A39BB2812"
      "5D5FB29BCB4C2920FD231DB297307FE93727795DB1C37715ADAA62737A4DA13E"
      "0504EC7E42B60823667B1C69E2DF891355573B713C8CCB3533BCBC4BBCFFAB58"
      "B22EF2991D68642FFFF4E6C753C827A37A966638A16C23D41CB93CD638CB031B"
      "46F34257454B3D017077611070C9CA3ADFFA040987E52A2A363463A1D28F0076"
      "7046BD023636C0C3939965B380FB22154923A0EB19F28570093BF2C5208C85CC"
      "F69BFD00C30F731FF453F28CC6FCF1EA7FA4660C5547363CC6DB47ADBC2D034E"
      "4C46756087269CB9AC24644EE2CF632326BCBFE3479D61B1721D95C2A856E909"
      "2C39F2060E2F26131F2DCA79506915258B17DA7753ECFFAD6CB3F40918EE801D"
      "6776219A8C741A028BC9649ED8E704C1F119DBE277822A135E069E338DFF1245"
      "199FB0363B68F12FE377CFEFC05F4CEBDBA130AC3E5ABB68FB38D8ECC6164077"
      "808F635D9C5390E4E67E34025FCD58330F979A8AF77EFDC281EB06DA37FACB0E"
      "6AFC42D58253C64390A955C01C02412F68BE5C0F141F550AC9083E160D1CB27E"
      "6104C5EAA0BCCE3A0EBEB3675BB1394D7844D6EA7C9BB70626EBC8459F584925"
      "B2D4F3F7DFA46C34BF6F5FE04BB842965A75B4714003F5C20D8279E2183D6D54"
      "CCEE840C9A76BCB83F633B98E4E141BFF5EE1D8DCCC4F2932C693A1A5ED474DE"};
  // RFC-5054 Test vector reference values for test purposes
  const std::string _usernameRFC5054TestVectorValue{"alice"};
  const std::string _passwordRFC5054TestVectorValue{"password123"};
  const std::string _saltRFC5054TestVectorValue{
      "BEB25379D1A8581EB5A727673A2441EE"};
  const std::string _kMultiplierRFC5054TestVectorValue{
      "7556AA045AEF2CDD07ABAF0F665C3E818913186F"};
  const std::string _xRFC5054TestVectorValue{
      "94B7555AABE9127CC58CCF4993DB6CF84D16C124"};
  const std::string _vRFC5054TestVectorValue{
      "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA"
      "1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F84"
      "00BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E"
      "26480D78E955A5E29E7AB245DB2BE315E2099AFB"};
  const std::string _aRFC5054TestVectorValue{
      "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393"};
  const std::string _bRFC5054TestVectorValue{
      "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20"};
  const std::string _A_RFC5054TestVectorValue{
      "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C046"
      "92272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED8251"
      "71E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFD"
      "FE15EFEAB349EF5D76988A3672FAC47B0769447B"};
  const std::string _B_RFC5054TestVectorValue{
      "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A067"
      "0DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885"
      "D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1"
      "B27AAEAEEB4012B7D7665238A8E3FB004B117B58"};
  const std::string _uRFC5054TestVectorValue{
      "CE38B9593487DA98554ED47D70A7AE5F462EF019"};
  const std::string _S_RFC5054TestVectorValue{
      "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220"
      "F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A"
      "0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4E"
      "C0A3212DC346D7E474B29EDE8A469FFECA686E5A"};
  const std::string _hashNameRFC5054TestVectorValue{"SHA-1"};
};

/**
 * @test Test the correctness of the construction of the structure of Session
 * Data.
 * @brief Test the correctness of the construction of the structure of Session
 * Data, should match the expected values.
 */
TEST_F(SessionDataTest,
       SessionData_WithValidInputParameters_ShouldMatchReference) {
  const unsigned int groupId{5};
  const std::string salt{
      "8F03FE9E9F8988BE043F4D17489E7EF9BD2FA3E1B1ADA0A286F16F8E9AD4BB06"};
  const std::string hash{"SHA-256"};
  const bool debugFlag{false};
  SessionData session(groupId, salt, hash, debugFlag);
  EXPECT_EQ(session._groupId, groupId);
  EXPECT_EQ(session._salt, salt);
  EXPECT_EQ(session._hash, hash);
}

/**
 * @test Test that the constructor of SessionData throws an error when
 * an invalid group ID is given as input parameter.
 * @brief Test that the constructor of SessionData throws an error when
 * an invalid group ID is given as input parameter. The error message
 * should match the expected value.
 */
TEST_F(SessionDataTest, SessionData_WithInvalidGroupId_ShouldThrowAnError) {
  const unsigned int groupId{0};
  const std::string salt{
      "8F03FE9E9F8988BE043F4D17489E7EF9BD2FA3E1B1ADA0A286F16F8E9AD4BB06"};
  const std::string hash{"SHA-256"};
  const bool debugFlag{false};
  try {
    SessionData session(groupId, salt, hash, debugFlag);
  } catch (const std::invalid_argument &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith("Invalid input parameters given."));
  }
}

/**
 * @test Test that the constructor of SessionData throws an error when
 * an invalid salt is given as input parameter.
 * @brief Test that the constructor of SessionData throws an error when
 * an invalid salt is given as input parameter. The error message
 * should match the expected value.
 */
TEST_F(SessionDataTest, SessionData_WithInvalidSalt_ShouldThrowAnError) {
  const unsigned int groupId{5};
  const std::string salt{""};
  const std::string hash{"SHA-256"};
  const bool debugFlag{false};
  try {
    SessionData session(groupId, salt, hash, debugFlag);
  } catch (const std::invalid_argument &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith("Invalid input parameters given."));
  }
}

/**
 * @test Test that the constructor of SessionData throws an error when
 * an invalid hash is given as input parameter.
 * @brief Test that the constructor of SessionData throws an error when
 * an invalid hash is given as input parameter. The error message
 * should match the expected value.
 */
TEST_F(SessionDataTest, SessionData_WithInvalidHash_ShouldThrowAnError) {
  const unsigned int groupId{5};
  const std::string salt{
      "8F03FE9E9F8988BE043F4D17489E7EF9BD2FA3E1B1ADA0A286F16F8E9AD4BB06"};
  const std::string hash{""};
  const bool debugFlag{false};
  try {
    SessionData session(groupId, salt, hash, debugFlag);
  } catch (const std::invalid_argument &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith("Invalid input parameters given."));
  }
}

/**
 * @test Test that the k multiplier map returned from the session data
 * matches the reference.
 * @brief Test that the k multiplier map returned from the session data
 * matches the reference. The k values are stored by group ID.
 */
TEST_F(SessionDataTest, SessionData_GetKMultiplierMap_ShouldMatchReference) {
  const unsigned int groupId{5};
  const std::string salt{
      "8F03FE9E9F8988BE043F4D17489E7EF9BD2FA3E1B1ADA0A286F16F8E9AD4BB06"};
  const std::string hash{"SHA-256"};
  const bool debugFlag{false};
  SessionData session(groupId, salt, hash, debugFlag);
  const std::map<unsigned int, MessageExtractionFacility::UniqueBIGNUM> &kMap{
      session._secureRemotePassword->getKMap()};
  const unsigned int groupsSize{7};
  // Test to RFC-5054 test vector
  EXPECT_EQ(
      MessageExtractionFacility::BIGNUMToHex(
          MyCryptoLibrary::SecureRemotePassword::calculateK(
              _srpParametersMap.at(1)._nHex,
              MessageExtractionFacility::uintToHex(_srpParametersMap.at(1)._g),
              _hashNameRFC5054TestVectorValue)
              .get()),
      _kMultiplierRFC5054TestVectorValue);
  // Test to the several group ID's
  EXPECT_EQ(kMap.size(), groupsSize);
  EXPECT_EQ(MessageExtractionFacility::BIGNUMToHex(kMap.at(1).get()),
            "1A1A4C140CDE70AE360C1EC33A33155B1022DF951732A476A862EB3AB8206A5C");
  EXPECT_EQ(MessageExtractionFacility::BIGNUMToHex(kMap.at(2).get()),
            "B2286EEE1033FE2BDC950CBF0ABB6FB56670E2B4D5BDA4CB203A9A96D018625D");
  EXPECT_EQ(MessageExtractionFacility::BIGNUMToHex(kMap.at(3).get()),
            "05B9E8EF059C6B32EA59FC1D322D37F04AA30BAE5AA9003B8321E21DDB04E300");
  EXPECT_EQ(MessageExtractionFacility::BIGNUMToHex(kMap.at(4).get()),
            "081F4874FA543A371B49A670402FDA59ECFAB53A1B850FC42E1C357CC846111E");
  EXPECT_EQ(MessageExtractionFacility::BIGNUMToHex(kMap.at(5).get()),
            "13ED8E2B1E3F847DA7D4BE9DDE56C9AD9AA50EE67CDC948E4053A171EBB384DF5D"
            "6B2047D295C857C61B9504CAF00907");
  EXPECT_EQ(MessageExtractionFacility::BIGNUMToHex(kMap.at(6).get()),
            "E23815ED6634AFD9F6C2EFC31B593068347B5AF87A072252A53F18019CCDB30E75"
            "1C17AD439E1A65DB22D67EF3C181CD806CDBBA608718785707156F998C4198");
  EXPECT_EQ(MessageExtractionFacility::BIGNUMToHex(kMap.at(7).get()),
            "4D52644EEB89DCEB292AEA0DC86CF8D1EE820E92B7F840F2E075004249315CE5EB"
            "61FD1FE6F8DC35E51495357EC0B4E14CAF9EF159D093BAD019514927476AC5");
}

/**
 * @test Test the correctness of the calculation of the SRP public key A
 * (client) using the RFC-5054 test vector for group 1.
 * @brief Verifies that the public key A, computed from known a, N, and g
 * values, matches the expected reference value from RFC-5054.
 */
TEST_F(SessionDataTest,
       CalculatePublicKeyClientWithRFC5054TestVector_ShouldMatchReference) {
  const unsigned int groupId{1};
  const std::string privateKeyHex{_aRFC5054TestVectorValue};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string gHex{
      MessageExtractionFacility::uintToHex(_srpParametersMap.at(groupId)._g)};
  const bool isServer{false};
  const std::string expectedAHex{_A_RFC5054TestVectorValue};
  std::string AHex{MyCryptoLibrary::SecureRemotePassword::calculatePublicKey(
      privateKeyHex, NHex, gHex, isServer)};
  EXPECT_EQ(AHex, expectedAHex);
  // Check that 1 < A < N
  MessageExtractionFacility::UniqueBIGNUM A_Bn{
      MessageExtractionFacility::hexToUniqueBIGNUM(AHex)};
  MessageExtractionFacility::UniqueBIGNUM N_Bn{
      MessageExtractionFacility::hexToUniqueBIGNUM(NHex)};
  EXPECT_GT(BN_cmp(A_Bn.get(), BN_value_one()), 0);
  EXPECT_LT(BN_cmp(A_Bn.get(), N_Bn.get()), 0);
}

/**
 * @test Test the correctness of the calculation of the SRP public key B
 * (server) using the RFC-5054 test vector for group 1.
 * @brief Verifies that the public key B, computed from known b, N, g, k, and v
 * values, matches the expected reference value from RFC-5054.
 */
TEST_F(SessionDataTest,
       CalculatePublicKeyServerWithRFC5054TestVector_ShouldMatchReference) {
  const unsigned int groupId{1};
  const std::string privateKeyHex{_bRFC5054TestVectorValue};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string gHex{
      MessageExtractionFacility::uintToHex(_srpParametersMap.at(groupId)._g)};
  const bool isServer{true};
  // k as BIGNUM
  MessageExtractionFacility::UniqueBIGNUM kBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(
          _kMultiplierRFC5054TestVectorValue)};
  const std::string vHex{_vRFC5054TestVectorValue};
  const std::string expectedBHex{_B_RFC5054TestVectorValue};
  std::string BHex{MyCryptoLibrary::SecureRemotePassword::calculatePublicKey(
      privateKeyHex, NHex, gHex, isServer, kBn.get(), vHex)};
  EXPECT_EQ(BHex, expectedBHex);
  // Check that 1 < B < N
  MessageExtractionFacility::UniqueBIGNUM B_Bn{
      MessageExtractionFacility::hexToUniqueBIGNUM(BHex)};
  MessageExtractionFacility::UniqueBIGNUM N_Bn{
      MessageExtractionFacility::hexToUniqueBIGNUM(NHex)};
  EXPECT_GT(BN_cmp(B_Bn.get(), BN_value_one()), 0);
  EXPECT_LT(BN_cmp(B_Bn.get(), N_Bn.get()), 0);
}

/**
 * @test Test the correctness of the calculation of the u = H(A | B)
 * parameter with SHA-1.
 * @brief Verifies that the scrambling parameter u, computed from known A and
 * B values using SHA-1, matches the expected reference value and has the
 * correct length, using as inputs the RFC-5054 test vector.
 */
TEST_F(SessionDataTest,
       calculateHashConcatWithSHA1RFC5054TestVector_ShouldMatchReference) {
  std::string hashName{"SHA-1"};
  std::string uHex{MyCryptoLibrary::SecureRemotePassword::calculateHashConcat(
      hashName,
      MessageExtractionFacility::hexToPlaintext(_A_RFC5054TestVectorValue),
      MessageExtractionFacility::hexToPlaintext(_B_RFC5054TestVectorValue))};
  EXPECT_EQ(uHex.length(), SHA_DIGEST_LENGTH * 2);
  EXPECT_EQ(uHex, _uRFC5054TestVectorValue);
}

/**
 * @test Test the correctness of the calculation of the u = H(A | B)
 * parameter with SHA-256.
 * @brief Verifies that the scrambling parameter u, computed from known A and
 * B values using SHA-256, matches the expected reference value and has the
 * correct length.
 */
TEST_F(SessionDataTest, calculateHashConcatWithSHA256_ShouldMatchReference) {
  std::string hashName{"SHA-256"};
  std::string uHex{MyCryptoLibrary::SecureRemotePassword::calculateHashConcat(
      hashName, MessageExtractionFacility::hexToPlaintext(_A_Hex),
      MessageExtractionFacility::hexToPlaintext(_B_Hex))};
  std::string expectedUHex{
      "49510A0BB9F42F1068F4446E620A4DF30453369329F2A001EF33A72510AA1810"};
  EXPECT_EQ(uHex.length(), SHA256_DIGEST_LENGTH * 2);
  EXPECT_EQ(uHex, expectedUHex);
}

/**
 * @test Test the correctness of the calculation of the u = H(A | B)
 * parameter with SHA-384.
 * @brief Verifies that the scrambling parameter u, computed from known A and
 * B values using SHA-384, matches the expected reference value and has the
 * correct length.
 */
TEST_F(SessionDataTest, calculateHashConcatWithSHA384_ShouldMatchReference) {
  std::string hashName{"SHA-384"};
  std::string uHex{MyCryptoLibrary::SecureRemotePassword::calculateHashConcat(
      hashName, MessageExtractionFacility::hexToPlaintext(_A_Hex),
      MessageExtractionFacility::hexToPlaintext(_B_Hex))};
  std::string expectedUHex{
      "0314B21EC992117D9C5F683036DD2F475EC67FE8E645534598B728CB32B4CB5A"
      "0140F855718AFE6C1D03A44E2B5639EC"};
  EXPECT_EQ(uHex.length(), SHA384_DIGEST_LENGTH * 2);
  EXPECT_EQ(uHex, expectedUHex);
}

/**
 * @test Test the correctness of the calculation of the u = H(A | B)
 * parameter with SHA-512.
 * @brief Verifies that the scrambling parameter u, computed from known A and
 * B values using SHA-512, matches the expected reference value and has the
 * correct length.
 */
TEST_F(SessionDataTest, calculateHashConcatWithSHA512_ShouldMatchReference) {
  std::string hashName{"SHA-512"};
  std::string uHex{MyCryptoLibrary::SecureRemotePassword::calculateHashConcat(
      hashName, MessageExtractionFacility::hexToPlaintext(_A_Hex),
      MessageExtractionFacility::hexToPlaintext(_B_Hex))};
  std::string expectedUHex{
      "AB6BDCAAC999E71946DA5047698DD4EAA2146D8097D03628E394880D6D21672D"
      "C12EEEC2BD18C4050E6D725C3FAC7D86CA10A79F3A08E277A872B521C4742CDF"};
  EXPECT_EQ(uHex.length(), SHA512_DIGEST_LENGTH * 2);
  EXPECT_EQ(uHex, expectedUHex);
}

/**
 * @test Test that during the u calculation, it throws an exception for
 * an unknown hash name.
 * @brief Verifies that the calculateHashConcat method throws
 * std::invalid_argument when an unsupported hash algorithm is provided.
 */
TEST_F(SessionDataTest,
       calculateHashConcat_WithUnknownHash_ShouldThrowRuntimeError) {
  const std::string unknownHash{"unknownHash"};
  try {
    MyCryptoLibrary::SecureRemotePassword::calculateHashConcat(
        unknownHash, MessageExtractionFacility::hexToPlaintext(_A_Hex),
        MessageExtractionFacility::hexToPlaintext(_B_Hex));
  } catch (const std::invalid_argument &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith("hash algorithm not recognized."));
  }
}

/**
 * @test Test that during the u calculation, it throws an exception with
 * empty input parameters.
 * @brief Verifies that the calculateHashConcat method throws
 * std::invalid_argument when empty input parameters are provided.
 */
TEST_F(SessionDataTest,
       calculateHashConcat_WithEmptyInputParameters_ShouldThrowRuntimeError) {
  const std::string hash{"SHA-256"};
  const std::string leftEmpty{}, rightEmpty{};
  try {
    MyCryptoLibrary::SecureRemotePassword::calculateHashConcat(hash, leftEmpty,
                                                               rightEmpty);
  } catch (const std::invalid_argument &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith(
                    "invalid input parameters received, cannot be empty."));
  }
}

/**
 * @test Test the correctness of the calculation of the x parameter with
 * SHA-1 according to the RFC-5054 test vector.
 * @brief Verifies that the private key parameter x, computed as
 * x = H(salt | H(username | ":" | password))
 * using SHA-1, matches the expected reference value for known
 * input values. This ensures the implementation of x generation is correct
 * and compatible with other SRP implementations.
 */
TEST_F(SessionDataTest,
       CalculateXWithSHA1RFC5054TestVector_ShouldMatchReference) {
  const std::string x{MyCryptoLibrary::SecureRemotePassword::calculateX(
      _hashNameRFC5054TestVectorValue, _usernameRFC5054TestVectorValue,
      _passwordRFC5054TestVectorValue, _saltRFC5054TestVectorValue)};
  EXPECT_EQ(x, _xRFC5054TestVectorValue);
}

/**
 * @test Test the correctness of the calculation of the x parameter with
 * SHA-256.
 * @brief Verifies that the private key parameter x, computed as x = H(salt |
 * password) using SHA-256, matches the expected reference value for known
 * input values. This ensures the implementation of x generation is correct
 * and compatible with other SRP implementations.
 */
TEST_F(SessionDataTest, CalculateXWithSHA256_ShouldMatchReference) {
  const std::string hash{"SHA-256"};
  const std::string salt{
      "3F455AE2504D25D0E5A24E363358CD58A3E41EB18AD066FEB81A7A1E82369DED"};
  const std::string password{"correct horse battery staple"};
  const std::string expectedX{
      "05CD5AE5950F4508FFB0ECEDD0677D4EB21DF7197ABBCF99C0FE8F815618B36C"};
  const std::string x{MyCryptoLibrary::SecureRemotePassword::calculateX(
      hash, _username, password, salt)};
  EXPECT_EQ(x, expectedX);
}

/**
 * @test Test the correctness of the calculation of the x parameter with
 * SHA-384.
 * @brief Verifies that the private key parameter x, computed as x = H(salt |
 * password) using SHA-384, matches the expected reference value for known
 * input values. This ensures the implementation of x generation is correct
 * and compatible with other SRP implementations.
 */
TEST_F(SessionDataTest, CalculateXWithSHA384_ShouldMatchReference) {
  const std::string hash{"SHA-384"};
  const std::string salt{"BFB160DEA15A3E9C974E1797AA02F8B1F0FBE6D97AA18E40577"
                         "C07A9E2F40BB02C8F612B42BADBCBE37691B9A2382B30"};
  const std::string password{"correct horse battery staple"};
  const std::string expectedX{
      "491F06E71E720BE1445BF94374ECB6979BC444D10896F219F80D900F907BCFA57B55DFD7"
      "B50568309E8DFDD3EF5BFD79"};
  const std::string x{MyCryptoLibrary::SecureRemotePassword::calculateX(
      hash, _username, password, salt)};
  EXPECT_EQ(x, expectedX);
}

/**
 * @test Test the correctness of the calculation of the x parameter with
 * SHA-512.
 * @brief Verifies that the private key parameter x, computed as x = H(salt |
 * password) using SHA-512, matches the expected reference value for known
 * input values. This ensures the implementation of x generation is correct
 * and compatible with other SRP implementations.
 */
TEST_F(SessionDataTest, CalculateXWithSHA512_ShouldMatchReference) {
  const std::string hash{"SHA-512"};
  const std::string salt{
      "6B479DEBFE96BB93AC51E60F534536E4E493549EE1DA41A145E415612FFBA766A2CEAF"
      "2BFB2DAF34585EF383E860EBD6C44627FAE2B88341F9BDA494A8B55D62"};
  const std::string password{"correct horse battery staple"};
  const std::string expectedX{
      "0A2F9B27C8CA003ED59F0A03767B8E62983A13D934DDA4A0ED0F03253F83D613DF727DDC"
      "82A4AC73FBB9D211F8EB35B0DA077824D7E5AD17F9ACA28C65BE614F"};
  const std::string x{MyCryptoLibrary::SecureRemotePassword::calculateX(
      hash, _username, password, salt)};
  EXPECT_EQ(x, expectedX);
}

/**
 * @test Test that during the X calculation, it throws an exception when
 * an unknown hash name is provided.
 * @brief Verifies that the calculateX method throws
 * std::invalid_argument when an unsupported hash algorithm is provided.
 */
TEST_F(SessionDataTest, CalculateXUnknownHash_ShouldThrowAnError) {
  try {
    const std::string unknownHash{"unknownHash"};
    const std::string salt{
        "6B479DEBFE96BB93AC51E60F534536E4E493549EE1DA41A145E415612FFBA766A2CEAF"
        "2BFB2DAF34585EF383E860EBD6C44627FAE2B88341F9BDA494A8B55D62"};
    const std::string password{"correct horse battery staple"};
    const std::string x{MyCryptoLibrary::SecureRemotePassword::calculateX(
        unknownHash, _username, password, salt)};
  } catch (const std::invalid_argument &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith("hash algorithm not recognized."));
  }
}

/**
 * @test Test the correctness of the SRP S parameter calculation for group
 * ID 1 with the input values of the test vector of the RFC-5054.
 * @brief Verifies that the client side S calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest,
       CalculateSClientGroup1RFC5054TestVector_ShouldMatchReference) {
  const unsigned int groupId{1};
  const unsigned int g{_srpParametersMap.at(groupId)._g};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string S{MyCryptoLibrary::SecureRemotePassword::calculateSClient(
      _B_RFC5054TestVectorValue, _kMultiplierRFC5054TestVectorValue, g,
      _xRFC5054TestVectorValue, _aRFC5054TestVectorValue,
      _uRFC5054TestVectorValue, NHex)};
  EXPECT_EQ(S, _S_RFC5054TestVectorValue);
}

/**
 * @test Test the correctness of the SRP S parameter calculation for group
 * ID 1.
 * @brief Verifies that the client side S calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateSClientGroup1_ShouldMatchReference) {
  const unsigned int groupId{1};
  const std::string kHex{
      MessageExtractionFacility::BIGNUMToHex(_kMap.at(groupId).get())};
  const unsigned int g{_srpParametersMap.at(groupId)._g};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string S{MyCryptoLibrary::SecureRemotePassword::calculateSClient(
      _BHex, kHex, g, _xHex, _aHex, _uHex, NHex)};
  const std::string expectedS{
      "4398E45A6D27D7BD611C581328A37B1E368C56BE846B5CD64DE83B6588B69F0A99"
      "9CDF7E886F18E520AFD53BE717E2DBAA364B61136E3B2884EE472F930577F866EC"
      "DE9044E3B0F583A3BDC3E5044D87FA6427B79F71A9A2E670B9D70069FC39817174"
      "14F845B49D88EE96D2537D38069255D78EF8D336AF148BDDFD6E7FA818"};
  EXPECT_EQ(S, expectedS);
}

/**
 * @test Test the correctness of the SRP S parameter calculation for group
 * ID 2.
 * @brief Verifies that the client side S calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateSClientGroup2_ShouldMatchReference) {
  const unsigned int groupId{2};
  const std::string kHex{
      MessageExtractionFacility::BIGNUMToHex(_kMap.at(groupId).get())};
  const unsigned int g{_srpParametersMap.at(groupId)._g};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string S{MyCryptoLibrary::SecureRemotePassword::calculateSClient(
      _BHex, kHex, g, _xHex, _aHex, _uHex, NHex)};
  const std::string expectedS{
      "716013AAB9CCA511E6387655A9A5B24F672C62BA6CE3477D63C23997A055ACEA062A"
      "15F2998A909503247906C385BB7C36913C0F2F6CF8C003FC0EB56CD8BD15C311E174"
      "712706C74BB73AF59511061175ED6C328C46D386A906C178A595E11F1ABFA8C5D673"
      "7480D0B507DD31985BD9108C819381D167D7F5D973D57DCAA876E631578B731DD604"
      "70C3302329D5823137A56C9C09A63CAF9D55B3AA92FC54EE888A30BC0296A62A061D"
      "3DB5164A72A684EDE20505CD41D888F0C34C669DC022"};
  EXPECT_EQ(S, expectedS);
}

/**
 * @test Test the correctness of the SRP S parameter calculation for group
 * ID 3.
 * @brief Verifies that the client side S calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateSClientGroup3_ShouldMatchReference) {
  const unsigned int groupId{3};
  const std::string kHex{
      MessageExtractionFacility::BIGNUMToHex(_kMap.at(groupId).get())};
  const unsigned int g{_srpParametersMap.at(groupId)._g};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string S{MyCryptoLibrary::SecureRemotePassword::calculateSClient(
      _BHex, kHex, g, _xHex, _aHex, _uHex, NHex)};
  const std::string expectedS{
      "3B9DC69549A728745A930D0C6B1BF8E77B46BCDE5214E511DD8F409256AD228D25E1"
      "E5F24237C9FC5A305D0ABA39C4743D536AACA8DA981432A2B1BFD4E3AD05B2F4EEB9"
      "75E31BEE3822A1DBCFBBFA2177B7B5C9DE33E755E77D0A57F11A51BE32342AD85B36"
      "DD869A9ED7D5696F0275E101DF673C5C36A9A8490F9AF272A29FBB3825C395A3AA93"
      "D9E5F9CC8F692C1C4A71CDAEC99E723BED4A4FD7D4908AA0D58A0D521BD2337FB943"
      "0B89B396EDAB2094F519555AAA15BE86E5C9E4F571F7C30231B99AEDD77DC985B83D"
      "126318C9D0BFA4BC9861DDF27C74B15EA597C3D750DD46F9F9D927810313065CD40C"
      "258B5378DF32CFA1D0358E6FF764A01DA9AE"};
  EXPECT_EQ(S, expectedS);
}

/**
 * @test Test the correctness of the SRP S parameter calculation for group
 * ID 4.
 * @brief Verifies that the client side S calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateSClientGroup4_ShouldMatchReference) {
  const unsigned int groupId{4};
  const std::string kHex{
      MessageExtractionFacility::BIGNUMToHex(_kMap.at(groupId).get())};
  const unsigned int g{_srpParametersMap.at(groupId)._g};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string S{MyCryptoLibrary::SecureRemotePassword::calculateSClient(
      _BHex, kHex, g, _xHex, _aHex, _uHex, NHex)};
  const std::string expectedS{
      "B736BEADDFB3E1DF75ADE7E4876C4E59B0513257809BBAB03729C91570B855136488"
      "CBF671F1A5C2D5084FC8EED574EF27D8A9682FAA8416B0BF83F8548D5AC7D422CE18"
      "CCDB2B45B136F6A993FA98E2EE8A5CA606FBA8EF289346D1ABD4F5E2F597465E61B2"
      "C3E143A16911546315099819CE8CDE045EB02ED1B15FA918E3F6ACB45C9333C28802"
      "A83735C0416D9A753FB0C533ABDE8183F7FF3ECD619BA5490CE18A21D4CA2BC887BE"
      "2EEF84546E9CF3A8A62E0E71E7B3F3B12AFF819BC6932C1D49EEEEC5027B4C41959C"
      "2773B1025277697C4647C0B4F767AC26FAAD5E86207DE78845BD22C889ED46E335AA"
      "B3874A96CC5C670005EE82E8024B6E794B2BCF3BF80F26788E5354D7C7A84DD708C1"
      "B725FFDFB1E0D18912B976B440239F556C70970F9CC3FFC745EC995BC2B031552B51"
      "C3E566C8C882D9F2A28056728088689F4DB675DC91AA65AB201D9A2CE88D897F4483"
      "E83BDEC2A639AEB8261D0347D1C08EFCA315873A9E5E2FD6FEEA70C5BB7900D67770"
      "9196BF8BF85B63AE2C05"};
  EXPECT_EQ(S, expectedS);
}

/**
 * @test Test the correctness of the SRP S parameter calculation for group
 * ID 5.
 * @brief Verifies that the client side S calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateSClientGroup5_ShouldMatchReference) {
  const unsigned int groupId{5};
  const std::string kHex{
      MessageExtractionFacility::BIGNUMToHex(_kMap.at(groupId).get())};
  const unsigned int g{_srpParametersMap.at(groupId)._g};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string S{MyCryptoLibrary::SecureRemotePassword::calculateSClient(
      _BHex, kHex, g, _xHex, _aHex, _uHex, NHex)};
  const std::string expectedS{
      "3C33133F89EE37B39353281B41C48AFF0219BFE339842E16A1D715DB57551A2B505"
      "5EA486C865A6B597726289BD36E8109A66BCADCF5474927463CEF8FB6D595F4E598"
      "E3ED548AB916939D85DAEAC5497E106D8AC4B422B65E799C002228E03A26A8A7CEC"
      "B1023B27E9EB2C12E6C8A56260BFE464992772C34C3B81B6C836E5301F8AD52315A"
      "F2808179E3BA2A9786F0382755F706CC4103E36F4E07982C5E94E19BFCC180BEB05"
      "EDAF1748F4816994ADF3BA90ECB615E363804CD2EA58A13A8C0F6E2CF16E0256C01"
      "100CACCA16A36ABDC7EC5BAC38C60FAF4C99E7CA53CC16C0E69964DCBF749A06940"
      "7237C10AE363CCA3553248FB85298E4CDEF10CB7340268B3B4032276BE917F66A61"
      "26723D716C4D2DD82B7D5504840F32CB54EE474E75B9CBDE5457862D5BBE3D83A5C"
      "60B9F333C32515EF7C6F1E762EC0317D2ECD15BF6FCEE345C694F97FF8F6BEFDAE2"
      "7237DD59B0C3795C135B155E385C338B3D32E5E2C8282BD5ED70043D29AC220E65D"
      "6E379F8B9F2A92AFD75A5BA0643781313D904C2E8338E6EFC30AAC0800A68DC21CA"
      "588671F49228FCB2B6BDA13AF2150D700ACBF43AA029FB79B333977A24403E216E3"
      "908C40046DC21EEF9F1A5AEA5A505EC387F957F313B5D98B1FB086481E4BC389F61"
      "CFD4AEBD95195DBA78AF8713137F31F6973E479112ADF6DF701B4F366EFAD68A27D"
      "5752183B29A4974EF80"};
  EXPECT_EQ(S, expectedS);
}

/**
 * @test Test the correctness of the SRP S parameter calculation for group
 * ID 6.
 * @brief Verifies that the client side S calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateSClientGroup6_ShouldMatchReference) {
  const unsigned int groupId{6};
  const std::string kHex{
      MessageExtractionFacility::BIGNUMToHex(_kMap.at(groupId).get())};
  const unsigned int g{_srpParametersMap.at(groupId)._g};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string S{MyCryptoLibrary::SecureRemotePassword::calculateSClient(
      _BHex, kHex, g, _xHex, _aHex, _uHex, NHex)};
  const std::string expectedS{
      "EB8BEB81C71ED17AE4EBB1EB5525CD53E8A1135FA1A4649B1C47ABC437FCA640099"
      "6DFC3DEDB4AB40AD280DDEEEFA612F182A398A0CDE560E06CED1723F2793E955DC3"
      "741E0A7023F40EE23DD3AF91CB89FCB2077BE33AF8B4F6BD16F464EF5F37761EB02"
      "0C3E41A80561F3D5072211A04C3FA786841C3A3DA086C45C33B6A9FEF9FD47BDCCE"
      "8E979D26239CB0CB99C8F9992C684DA8DF06EB48B980FF26C7114D036C9D51F6F9F"
      "1B54F6EEE5246D7525375E7702E6D1BDF7DE45EA8537C647B27DDD10115CECC91BC"
      "647223D298E29C5D76C2AEEACB9E074F2786F517D5B33020CFC2CD5977DC2BBF744"
      "B19314BBC58DDA0E3EE1F92AC06C04AC382DC0B6722CCFB2E0A1931E86713F9FAF0"
      "EAF27A87FA121E96007366DBADBDF4B7F6D386EBACACAF9E9BA2474D4F8E24D862F"
      "6F4658C9CEFCD416335EBBACEE2828AE96ED30586862F4927B749CC7E200656E9DE"
      "F5C857F092DD58E967F58B317B5B6533804C531EB1C190358DB47539267E54A3E19"
      "561AA7F2799164CF971AA25C69AFCB1BA2D54382BC982261A69091A5D9BBED71649"
      "27FC1775E4F05AC4F45676CF26FB84B975DC92C2A72F38270EB74C3A17F9850E1AD"
      "AE7B97A9A8104ECAB8F2A2B4080815082C87B1967C04A5795FF7079C4D2A6CF7F27"
      "B6D8EE9AE81E22139731A8E8020144B310C89F943F4C292BBE2F4D53BF2245E3705"
      "90FBB10232F43331217D93C1E01657A941B8E582B5803C6AF9F019C655CCA0DD29D"
      "F832673460151D956985CFB81DB98F5A6AC030DCA216B4045F14E2AA113A54C0D62"
      "C36F7B3920E85971103225F22FADA3CEB96E94CA0A0AB5A6A987BC55C72704F0CB0"
      "130808B152F5F23582185CB7C88DB331C93454C0A005643AC1D92A4213C6EED3B58"
      "992A204EDC5BBCD9B492928F5E0BFDEC7AC2BFF2276CD48D90798142F58B1EED2B4"
      "72C71160E4AA006ADFE358186D6D43226D0A9D99002281A417826C3842868A6DBF2"
      "C0E397AAF08A8C47E3EC63B44F89681F0F204DAE8A14930F8F2380C3CCF2007BDAF"
      "98F7B5A0E3E1EFC9CEEBA527CB0FE605448648C2C9638A4BAC80ED1EFB2F28"};
  EXPECT_EQ(S, expectedS);
}

/**
 * @test Test the correctness of the SRP S parameter calculation for group
 * ID 7 at the client side.
 * @brief Verifies that the client side S calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateSClientGroup7_ShouldMatchReference) {
  const unsigned int groupId{7};
  const std::string kHex{
      MessageExtractionFacility::BIGNUMToHex(_kMap.at(groupId).get())};
  const unsigned int g{_srpParametersMap.at(groupId)._g};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string S{MyCryptoLibrary::SecureRemotePassword::calculateSClient(
      _BHex, kHex, g, _xHex, _aHex, _uHex, NHex)};
  const std::string expectedS{
      "059C7926144D7BDC2BBC6F2FB1C007AEF852B00B4320496A7D542F0BE68A328424E9"
      "6DDE623A2A4B6F7319285E0FD74F46830050AE91D0D0A72481F84E0411A6283AE6BF"
      "862B5849AA031C0D807514C743FBBB8057EA9DD2A24DE26EA8A23484B297AB9EFDB8"
      "8E7077420FF7B1D0A63D8A1F45E2824831A0FEA2C4F4BC2B5FC2C0AD6D986DE6BCB7"
      "59FD49B4109AA832A19A03DF03E79C7351E9CA3C9EBBC5DAAC28FC883A285E3F6AEC"
      "A0B4624780D030D82EDD4B790EFE1F87B6DEA140F34EAC5EF7F8B6849B10B1D9FBB6"
      "D771F7FED235FE3FF0C1D159A374426BD3A83492ED597BC050BA03BFFE2AF0B680C9"
      "AC6DC0785441DB2ECC795457A2D300A7D662DA62510907D4360BB5DE103CF3A3595F"
      "5325653D21293B62C8F3464C7742414AFB463669DA451C4B9412C782AD665CA4EE9D"
      "FB003CBEF2AB5A2E341A75DF0D5F5D957FD1F74E9D40469C1D000B967F23953B06C7"
      "EC1B1F907DE8933899004E2AFCF1B5297FCE69484B8D4657A021EE964CC6BC8F65AB"
      "2088302F8B0768FD884FD8E89C4F0451C7FF957E4DEB3799BADD546FD5295DAD1D88"
      "C1708CC42F1335752EDC427FA548F37F27AB8D98DB2E45DBB2B3CA0545C596B4E334"
      "B099A5B819695BAF6C3E1BA11F51D2493ECA2A086F11ABB99C77E1C51EC2322FAA17"
      "E9C6E46309064164725C033649EED64C886FCBFDAB7DAF5F77A243388F004C42288D"
      "73E7F4D39F57C92880314B7E749F25A3CCF9C35C0B59299F055524C2D326F434F251"
      "A16CB72E7BDA6A95B848CC2ED5CEEE40A17569FB2398E77D34429FAD0A3BC608A054"
      "93E6B5EA17FC65D774F28E4C4A5A97A7378CCF1FBFAD745EEDCC7D20C6DB1A7C87B6"
      "85AB6E8C3A983174B51D6D42E3E0E181DEA859EC37BFB2DE9AFC0261FFAB567CA8A9"
      "874788523B0F6FE02BF6FA2CB514BC5DC7514D95C1FACD18A832CF86AB44E9054D27"
      "E5A7A074DFDBDF4A41F845EDB28A9E2F57DD95468D2514813EA463CCCB7CCD426F09"
      "0150EB1D191EA7231DD7A6C08ED206B98F577906C8D27AAA599D83823115E14CAA74"
      "9DA92A32D3510B6B4117D341C5D375125949FF74479FEBA4FCF104B80F1EFAA84E00"
      "D80DC5890FA6CBDD2D70787B2122914C27371F8BC09E763879F53462A8440C4EAF8B"
      "E414DE7F6DE16B2D439CC670F9EFC0AF97876E0B0BC6518D848A879267E915EA6283"
      "C77AD2C89E0B0DF6DF08AFD122E21EF4900A0FBF07C0B97AD4519F087E8708BB483F"
      "9C1824209D5982586E7314FBA500FAAD44F6270D93F262381F6CE767C2619C2A4AC2"
      "CDB56487FC643841B14DF0A76A1CC2A385032B4894A14E61F81439BCF56A837D190B"
      "74B0581786FB90DF363517B295F3C39EB190EC75D007D1260D785F5C6B6C037ACF0B"
      "8E898786361062D21DB2D1B3E656BA982E14AD2C66D51D4C889BC2C507CE2CFA6B9D"
      "9CDCFCBC"};
  EXPECT_EQ(S, expectedS);
}

/**
 * @test Test the correctness of the SRP K parameter calculation with the
 * hash SHA-1.
 * @brief Verifies that K calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateKHash1_ShouldMatchReference) {
  const std::string hash{"SHA-1"};
  const std::string K{
      MyCryptoLibrary::SecureRemotePassword::calculateK(hash, _SHex)};
  const std::string expectedK_SHA1{"64025F1B480E8DEB71704F18E28BB7B7CC515B98"};
  EXPECT_EQ(K, expectedK_SHA1);
}

/**
 * @test Test the correctness of the SRP K parameter calculation with the
 * hash SHA-256.
 * @brief Verifies that K calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateKHash256_ShouldMatchReference) {
  const std::string hash{"SHA-256"};
  const std::string K{
      MyCryptoLibrary::SecureRemotePassword::calculateK(hash, _SHex)};
  const std::string expectedK_SHA256{
      "1AE0343EE601440CA0CE952F802AFA72F1A6AB454555CCBB25B604691AE10B25"};
  EXPECT_EQ(K, expectedK_SHA256);
}

/**
 * @test Test the correctness of the SRP K parameter calculation with the
 * hash SHA-384.
 * @brief Verifies that K calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateKHash384_ShouldMatchReference) {
  const std::string hash{"SHA-384"};
  const std::string K{
      MyCryptoLibrary::SecureRemotePassword::calculateK(hash, _SHex)};
  const std::string expectedK_SHA384{
      "63093E8FBDCB514F2ED56D7ADFFC3F720BC487CA0096D55532F705E178E6BE36"
      "326A785617241D3CEB7A7965066216D7"};
  EXPECT_EQ(K, expectedK_SHA384);
}

/**
 * @test Test the correctness of the SRP K parameter calculation with the
 * hash SHA-512.
 * @brief Verifies that K calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateKHash512_ShouldMatchReference) {
  const std::string hash{"SHA-512"};
  const std::string K{
      MyCryptoLibrary::SecureRemotePassword::calculateK(hash, _SHex)};
  const std::string expectedK_SHA512{
      "39FDCEC9D0DC0BD723318C18F55951C3BB9B442FDE6452AA5BAC2B8F6A2B61BF"
      "406C79A849C324AA0B3DD7854FB5C56763E305889689E04C8E83A95E244410E7"};
  EXPECT_EQ(K, expectedK_SHA512);
}

/**
 * @test Test that during the K calculation, it throws an exception when
 * an unknown hash name is provided.
 * @brief Verifies that the calculateK method throws
 * std::invalid_argument when an unsupported hash algorithm is provided.
 */
TEST_F(SessionDataTest, CalculateKUnknownHash_ShouldThrowAnError) {
  try {
    const std::string unknownHash{"unknownHash"};
    const std::string K{
        MyCryptoLibrary::SecureRemotePassword::calculateK(unknownHash, _SHex)};
  } catch (const std::invalid_argument &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith("hash algorithm not recognized."));
  }
}

/**
 * @test Test that during the K calculation, it throws an exception when
 * an empty input parameter is provided.
 * @brief Verifies that the calculateK method throws
 * std::invalid_argument when an empty input parameter is provided.
 */
TEST_F(SessionDataTest, CalculateKWithEmptyInputParameter_ShouldThrowAnError) {
  try {
    const std::string hash{"SHA-256"};
    const std::string emptyS{};
    const std::string K{
        MyCryptoLibrary::SecureRemotePassword::calculateK(hash, emptyS)};
  } catch (const std::invalid_argument &e) {
    EXPECT_THAT(std::string(e.what()), ::testing::EndsWith("SHex in empty."));
  }
}

/**
 * @test Test the correctness of the SRP M parameter (client's proof)
 * calculation with the hash SHA-1.
 * @brief Verifies that M calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateMHashSHA1_ShouldMatchReference) {
  const std::string hash{"SHA-1"};
  const unsigned int groupId{7};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string gHex{
      MessageExtractionFacility::uintToHex(_srpParametersMap.at(groupId)._g)};
  const std::string M{MyCryptoLibrary::SecureRemotePassword::calculateM(
      hash, NHex, gHex, _username, _saltHex, _A_Hex, _B_Hex, _KHex)};
  const std::string expectedM_SHA1{"0966DD8D340DC969DE7B10D1EE36E5EBC709040B"};
  EXPECT_EQ(M, expectedM_SHA1);
}

/**
 * @test Test the correctness of the SRP M parameter (client's proof)
 * calculation with the hash SHA-256.
 * @brief Verifies that M calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateMHashSHA256_ShouldMatchReference) {
  const std::string hash{"SHA-256"};
  const unsigned int groupId{7};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string gHex{
      MessageExtractionFacility::uintToHex(_srpParametersMap.at(groupId)._g)};
  const std::string M{MyCryptoLibrary::SecureRemotePassword::calculateM(
      hash, NHex, gHex, _username, _saltHex, _A_Hex, _B_Hex, _KHex)};
  const std::string expectedM_SHA256{
      "40CE6C8C3797FABF8BBB745BD897B3DA49A34DF022C6BA00C5CB3FE4AD7DFE78"};
  EXPECT_EQ(M, expectedM_SHA256);
}

/**
 * @test Test the correctness of the SRP M parameter (client's proof)
 * calculation with the hash SHA-384.
 * @brief Verifies that M calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateMHashSHA384_ShouldMatchReference) {
  const std::string hash{"SHA-384"};
  const unsigned int groupId{7};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string gHex{
      MessageExtractionFacility::uintToHex(_srpParametersMap.at(groupId)._g)};
  const std::string M{MyCryptoLibrary::SecureRemotePassword::calculateM(
      hash, NHex, gHex, _username, _saltHex, _A_Hex, _B_Hex, _KHex)};
  const std::string expectedM_SHA384{
      "50900EE69884E6F973BE913531587BE7825D03390557D3C04012504E71D77967"
      "80FEAEABE8CC6053F011D3712388AA3C"};
  EXPECT_EQ(M, expectedM_SHA384);
}

/**
 * @test Test the correctness of the SRP M parameter (client's proof)
 * calculation with the hash SHA-512.
 * @brief Verifies that M calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateMHashSHA512_ShouldMatchReference) {
  const std::string hash{"SHA-512"};
  const unsigned int groupId{7};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string gHex{
      MessageExtractionFacility::uintToHex(_srpParametersMap.at(groupId)._g)};
  const std::string M{MyCryptoLibrary::SecureRemotePassword::calculateM(
      hash, NHex, gHex, _username, _saltHex, _A_Hex, _B_Hex, _KHex)};
  const std::string expectedM_SHA512{
      "9583CD0DAC1491D6DFE73CE953460FC0C33F2B6CDA2651D79CF2458C2C2FD60F"
      "F5FD8FDC61391C5AFD09B939F141F78AC1D237A57408DEC11EF2659063C63D2F"};
  EXPECT_EQ(M, expectedM_SHA512);
}

/**
 * @test Test that during the M calculation, it throws an exception when
 * an unknown hash name is provided.
 * @brief Verifies that the calculateM method throws
 * std::invalid_argument when an unsupported hash algorithm is provided.
 */
TEST_F(SessionDataTest, CalculateMUnknownHash_ShouldThrowAnError) {
  try {
    const std::string hash{"UNKNOWN-HASH"};
    const unsigned int groupId{7};
    const std::string NHex{_srpParametersMap.at(groupId)._nHex};
    const std::string gHex{
        MessageExtractionFacility::uintToHex(_srpParametersMap.at(groupId)._g)};
    const std::string M{MyCryptoLibrary::SecureRemotePassword::calculateM(
        hash, NHex, gHex, _username, _saltHex, _A_Hex, _B_Hex, _KHex)};
  } catch (const std::invalid_argument &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith("hash algorithm not recognized."));
  }
}

/**
 * @test Test that during the M calculation, it throws an exception when
 * an empty input parameter is provided.
 * @brief Verifies that the calculateM method throws
 * std::invalid_argument when an empty input parameter is provided.
 */
TEST_F(SessionDataTest, CalculateMWithEmptyInputParameter_ShouldThrowAnError) {
  try {
    const std::string hash{"SHA-256"};
    const unsigned int groupId{7};
    const std::string NHexEmpty{};
    const std::string gHex{
        MessageExtractionFacility::uintToHex(_srpParametersMap.at(groupId)._g)};
    const std::string M{MyCryptoLibrary::SecureRemotePassword::calculateM(
        hash, NHexEmpty, gHex, _username, _saltHex, _A_Hex, _B_Hex, _KHex)};
  } catch (const std::invalid_argument &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith("empty input parameters received."));
  }
}

/**
 * @test Test the correctness of the SRP S parameter calculation for group
 * ID 1 at the server side, using the RFC-5054 test vectors.
 * @brief Verifies that the server side S calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest,
       CalculateSServerGroup1RFC5054TestVector_ShouldMatchReference) {
  const unsigned int groupId{1};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string S{MyCryptoLibrary::SecureRemotePassword::calculateSServer(
      _A_RFC5054TestVectorValue, _vRFC5054TestVectorValue,
      _uRFC5054TestVectorValue, _bRFC5054TestVectorValue, NHex)};
  EXPECT_EQ(S, _S_RFC5054TestVectorValue);
}

/**
 * @test Test the correctness of the SRP S parameter calculation for group
 * ID 7 at the server side.
 * @brief Verifies that the server side S calculation matches the expected
 * reference value.
 */
TEST_F(SessionDataTest, CalculateSServerGroup7_ShouldMatchReference) {
  const unsigned int groupId{7};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const std::string S{MyCryptoLibrary::SecureRemotePassword::calculateSServer(
      _A_Hex, _vHex, _uHex, _bHex, NHex)};
  const std::string expectedS{
      "0C6D558A61E9A9A4BB70C1EA12372EF29C38259B006869A612D26C425106B726AB949D61"
      "2CC94A650C0902A6F034F9B641355BC611C48104EFB35F976818AAAEBDC5E273E4849C32"
      "7E5DD8805F4851A040046CD8234276044C63C7BBAAB2A1EECCED2D86D921943B4EAAE19B"
      "F44C5D5A8FEC658D7780F0EBB08C1D75CFD954007CC2B2C0264EA1EC34A13151017FE935"
      "46651E66B803B887F550D5118A1236BE813E0AFC63AAFAFB823DD10304D396D482981A1F"
      "DFF43E50CD913390CAE456F4B91D5B73D8D958F3B92961DF2BB28C177364FCD25ABF6637"
      "056D32AD8AF15E97756F56DDEDC4E69CC8FA500B83E94B895EAF087A4B3878C26024395C"
      "0CA9FDBB82B91414A8E38F4D79B8D1522BC09C5A3397C981C2C51174782F12D3C7166B3C"
      "41B4816B6FC6D5D62A32494E74C153A7CD2B0888582924FC3F3C6FB5A9206003549DEBE5"
      "5DDAB8520BB918E74471B546EF85DCBEE09EDE9DA0F15E0DB9788821E330BB2FF7385FD3"
      "95CD78222AB24149B47A6555D17881DE582991245E02FE36825FA98F7BEB022B630BD04E"
      "5D6A1EB76DB96FBC61335C7C7DC7AF62743DEEDA1626ADB0B705220FBF18F6E74212A0CA"
      "FDA99395281A015F69DDEE8052CF7FE6F7313F3598804D81F6EA3C57CFB3956610940A3A"
      "7AE151B5D305EF60332C4441DEFA6E42FA034C6AA3BE89EBBD5BAEF61894F64DCF979424"
      "C18D9E0E6BC2D0A9C5D8478EC9E15E53C6ACE2FFCC72BDD28C212898BB577AA99FBA327F"
      "35F8E979FA60132FB4C0B8214326D8D1224E39468C95E5AB922EE7B3AE8CCE9191EA8E7C"
      "E64BC358800D9F5F9EF958640EED3DECBB65149685FC9DD17B2724F113A228CBA177C356"
      "BD6BF7F70112DDB73D16EEEFF44DB1941CDDEDCDEEF8BF7DF319CAD194B5BA830924279E"
      "042E2C835AE450926764E7F87F72D2957EDCD13508C2A17E6BE455CBF5E62B714217DD93"
      "C4CC386C8D674136912770BC066A394D02C723C47418F18D3ABBBA1060BE7C38A17C0D6A"
      "56527B8E1E2BAFA387B9F46BE94461E72D70DA59431B7CC083843139CA16A2EDFBF2851F"
      "A318E0693CEB2881202817701B02358326E07673FBF2DCCF7D7C4748B0699F5E6D21BFDA"
      "3FE0066FD18A92867FA661D5D3531D64F0D819F519CE7562B80E35636E3A9B4BD10D00AC"
      "CD6A780C429D76D46589CDA608ABA3F8348322761ED6EFAD135267A13D72FF56C8798074"
      "FA1E88B6EDDDDE5C320076347FA19D165C3C389A9D83BCFCC2D489701029B4A103C70800"
      "303F26956027A63130114E39725AF5629AF8B2E48685368C02065D50F3EF7D9E9E77D447"
      "084740083FF0D45D335D4558DA3AB17D487A260C80A87AA9D7E67FD207A43043A9AA5032"
      "379992E58DF49262ED2BF58A83CDF939BF5D5B11D76B4C601290FD8DD457D22D8BAD3985"
      "3E7879C59C0A10AB8EB3CD82D7A04E9B"};
  EXPECT_EQ(S, expectedS);
}

/**
 * @test Test that during the S calculation at the server side, it throws an
 * exception when invalid input parameters are provided.
 * @brief Verifies that the calculateSServer method throws
 * std::invalid_argument when invalid input parameters are provided.
 */
TEST_F(SessionDataTest,
       CalculateSServerInvalidInputParameters_ShouldThrowAnError) {
  try {
    const unsigned int groupId{7};
    const std::string NHexInvalid{""};
    const std::string S{MyCryptoLibrary::SecureRemotePassword::calculateSServer(
        _A_Hex, _vHex, _uHex, _bHex, NHexInvalid)};
  } catch (const std::invalid_argument &e) {
    EXPECT_THAT(std::string(e.what()),
                ::testing::EndsWith("One or more input parameters are empty."));
  }
}

/**
 * @test Test the correctness of the calculation of the SRP verifier v = g^x mod
 * N using the RFC-5054 test vector for group 1.
 * @brief Verifies that the verifier v, computed from known x, N, and g values,
 * matches the expected reference value from RFC-5054.
 */
TEST_F(SessionDataTest, CalculateVWithRFC5054TestVector_ShouldMatchReference) {
  const std::string xHex{_xRFC5054TestVectorValue};
  const std::string NHex{_srpParametersMap.at(1)._nHex};
  const unsigned int g{_srpParametersMap.at(1)._g};
  const std::string vHex{
      MyCryptoLibrary::SecureRemotePassword::calculateV(xHex, NHex, g)};
  EXPECT_EQ(vHex, _vRFC5054TestVectorValue);
  // Check that v is in the correct range: 1 < v < N
  MessageExtractionFacility::UniqueBIGNUM vBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(vHex)};
  MessageExtractionFacility::UniqueBIGNUM nBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(NHex)};
  EXPECT_GT(BN_cmp(vBn.get(), BN_value_one()), 0);
  EXPECT_LT(BN_cmp(vBn.get(), nBn.get()), 0);
}


/**
 * @test Test the correctness of the calculation of the SRP verifier v = g^x mod
 * N using the RFC-5054 test vector for group 2.
 * @brief Verifies that the verifier v, computed from known x, N, and g values,
 * matches the expected reference value from RFC-5054.
 */
TEST_F(SessionDataTest,
       CalculateVWithRFC5054TestVectorGroup2_ShouldMatchReference) {
  const unsigned int groupId{2};
  const std::string xHex{_xRFC5054TestVectorValue};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const unsigned int g{_srpParametersMap.at(groupId)._g};
  const std::string vHex{
      MyCryptoLibrary::SecureRemotePassword::calculateV(xHex, NHex, g)};
  const std::string vExpected{
      "661B6FEA4BBE1A09DF5A17A9ADF65D8AE890AA2F2EA450EFB5200A5C5DAE98FA2FF0677E"
      "BB8C70012CC41B344A18D10C79A64A7AC6B392DB99E0C8F16D7A50ADBE2955103DD38E5C"
      "5A287DA9F4264CF93FEDFF3AA6CE47F18A53EC41EA2E7BF36C53DE4B223266558DC0E6DD"
      "EC513E059B0879112637C7EDCA8516338A4B5ACF4D634133DB26BA80870B1EB342AD68C9"
      "56F71A03171D23A76A4C735199027155B40103CAECC131DED02A2664C4E17A0AAD2B204D"
      "600BB9BBDAB7387B130C00DD"};
  EXPECT_EQ(vHex, vExpected);
  // Check that v is in the correct range: 1 < v < N
  MessageExtractionFacility::UniqueBIGNUM vBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(vHex)};
  MessageExtractionFacility::UniqueBIGNUM nBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(NHex)};
  EXPECT_GT(BN_cmp(vBn.get(), BN_value_one()), 0);
  EXPECT_LT(BN_cmp(vBn.get(), nBn.get()), 0);
}

/**
 * @test Test the correctness of the calculation of the SRP verifier v = g^x mod
 * N using the RFC-5054 test vector for group 3.
 * @brief Verifies that the verifier v, computed from known x, N, and g values,
 * matches the expected reference value from RFC-5054.
 */
TEST_F(SessionDataTest,
       CalculateVWithRFC5054TestVectorGroup3_ShouldMatchReference) {
  const unsigned int groupId{3};
  const std::string xHex{_xRFC5054TestVectorValue};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const unsigned int g{_srpParametersMap.at(groupId)._g};
  const std::string vHex{
      MyCryptoLibrary::SecureRemotePassword::calculateV(xHex, NHex, g)};
  const std::string vExpected{
      "960C64FA1148B0074457E3EB45DB6F7929B368CD06C6C582FB39E5961178C8946D940DA7"
      "8BDC3E73F1A60CDBC7BBA2FBD83D31BC3906E986038455B81FB881FED4F8119B312138CE"
      "17AFC09B12BA91C9A49F2AB593993255138F6EC39E95F67294248DF9D95AAE72ACE37B95"
      "A747C6B35112E68B0F33A3C57563E0F75415084B5C6594179CB97A10ACEAC6338D1DEF7D"
      "CE73A0BD3689D5FEF55EBED63CBB4AC5B049E53A9D9B5075AB32F771F5EA881B92D29CD2"
      "7348328F3F9235B2A58CF43262365C1B1DD6B7D96BC2DF3AE70E1009E2CFEA30115DC226"
      "0C17C54BBF4AF223C773EE4BCF6DBEE2990CB484E38ADDFD0DF6BE7727CE1875EBCCF15F"
      "538B310C"};
  EXPECT_EQ(vHex, vExpected);
  // Check that v is in the correct range: 1 < v < N
  MessageExtractionFacility::UniqueBIGNUM vBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(vHex)};
  MessageExtractionFacility::UniqueBIGNUM nBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(NHex)};
  EXPECT_GT(BN_cmp(vBn.get(), BN_value_one()), 0);
  EXPECT_LT(BN_cmp(vBn.get(), nBn.get()), 0);
}

/**
 * @test Test the correctness of the calculation of the SRP verifier v = g^x mod
 * N using the RFC-5054 test vector for group 4.
 * @brief Verifies that the verifier v, computed from known x, N, and g values,
 * matches the expected reference value from RFC-5054.
 */
TEST_F(SessionDataTest,
       CalculateVWithRFC5054TestVectorGroup4_ShouldMatchReference) {
  const unsigned int groupId{4};
  const std::string xHex{_xRFC5054TestVectorValue};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const unsigned int g{_srpParametersMap.at(groupId)._g};
  const std::string vHex{
      MyCryptoLibrary::SecureRemotePassword::calculateV(xHex, NHex, g)};
  const std::string vExpected{
      "24CBD3A96ED900D33FA12BA65FB24DD2E45EF35658C0930BCECA6F50656C32F930BBDAD3"
      "B0BCF7790F8DD74E213EE25E3EB4749550F32CD07B8BB2F60006F3819DCA00AE13A20727"
      "DAD29339467DD9926670FBA4ADA87E719EBCA0F51FE8E427C965857B7B726DE324D0A256"
      "4906DA4CEBFC625E9482DA305C23026B19004759AE863B1FB906B5A97131BCF80A67D513"
      "9ED06CBD22AF1639627CF450735E52832D416ADB16DE0AC8DBDB9E31377AE48DE9097580"
      "D9B185007E0E5CCEE0499E8597F86A2AE74C2D931C27722F5B61B8827D422744368E7640"
      "6BFDCB08E1057AF858B3C17F2D1B2E9648B63F897C751044B1F90C5F9C262115CB28B383"
      "6106D40C62144D318232845145D7832D254A329F42276ADE4FE63D6D2748160DDB5E1A08"
      "64DEE473EE1CD59CAEF54D729E6417B710A923909C2B801CA2F211C6C782EFC6798B389C"
      "A7DDBBC9B3BC4F0F418F0AADB688221F40FED75DD535C59BDB4A74A6C217B28C4E6BE6F3"
      "A227FABE8EE94BC33EE6BEF9C5F368CBD90AA6D137249245"};
  EXPECT_EQ(vHex, vExpected);
  // Check that v is in the correct range: 1 < v < N
  MessageExtractionFacility::UniqueBIGNUM vBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(vHex)};
  MessageExtractionFacility::UniqueBIGNUM nBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(NHex)};
  EXPECT_GT(BN_cmp(vBn.get(), BN_value_one()), 0);
  EXPECT_LT(BN_cmp(vBn.get(), nBn.get()), 0);
}

/**
 * @test Test the correctness of the calculation of the SRP verifier v = g^x mod
 * N using the RFC-5054 test vector for group 5.
 * @brief Verifies that the verifier v, computed from known x, N, and g values,
 * matches the expected reference value from RFC-5054.
 */
TEST_F(SessionDataTest,
       CalculateVWithRFC5054TestVectorGroup5_ShouldMatchReference) {
  const unsigned int groupId{5};
  const std::string xHex{_xRFC5054TestVectorValue};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const unsigned int g{_srpParametersMap.at(groupId)._g};
  const std::string vHex{
      MyCryptoLibrary::SecureRemotePassword::calculateV(xHex, NHex, g)};
  const std::string vExpected{
      "30716D4386A077C18F80259CE80B9F4A15015F2ECFDF3968E2B057B5BDDAD3DD9150DC1F"
      "82F450B8CC0F41CA6F5145B99A30CBCDE2FDDEA420C0218E8446D22EE25EB74F960C31A5"
      "6FFE975B2BCCF3A18DA7F9C146CDD8ACD432695EEF4B4F28F889A09FC7EFA4053AECAA07"
      "137707F670642220569B9C5EDE52BFE3E0976DF7BF5F75B513832D8F26A02AF4308061DB"
      "7DF2F694D4828AB14354A02D466884AEE59593079094198187EBC6BAEE861501D7BF3FFC"
      "D712AD1780237EF2486E9B70BD3C0B2F386E775D115040B481D63CC4B2D978D9BCEA3AA1"
      "87D33A55F087623474357E37CB94F6909E34E7CBB1C10FF61D587721FDFB63C313A80B39"
      "295FED0E4A29A3CBE6C9A8BCA9B9D454B3AB744026E33ACCFF7D1B67A2F12B8D76EB3153"
      "31ED261FACBCA7B21F434E3021603A479B4CDCA5E0EBEC0E69386233EC803B4F38B50F5C"
      "7D91CC7E78CE766494A9C5B7CFF844946FBB96189AFF9EACC34EDCABE56BB66085766993"
      "36E1B53E13C14B0B1B6D17E449DF3B3D6AD29FE1AB7A22FEF7F4465063D35263DF4A161C"
      "37DF117E0E6CD9C98F2291E8D243DF729A40800AE426260D6923CBF342B29C4F22E83199"
      "CCA9897E7C5C94C682167FF32BF5693413C0455BEFBEE0571243E31D3AD19EE48DE853AD"
      "7A3FE29070BC1DB48C964892AF73590878F957DA1D5660F7B68B1B8C86F13251A25DFD9D"
      "FD8C2ABF34CD44DD"};
  EXPECT_EQ(vHex, vExpected);
  // Check that v is in the correct range: 1 < v < N
  MessageExtractionFacility::UniqueBIGNUM vBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(vHex)};
  MessageExtractionFacility::UniqueBIGNUM nBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(NHex)};
  EXPECT_GT(BN_cmp(vBn.get(), BN_value_one()), 0);
  EXPECT_LT(BN_cmp(vBn.get(), nBn.get()), 0);
}

/**
 * @test Test the correctness of the calculation of the SRP verifier v = g^x mod
 * N using the RFC-5054 test vector for group 6.
 * @brief Verifies that the verifier v, computed from known x, N, and g values,
 * matches the expected reference value from RFC-5054.
 */
TEST_F(SessionDataTest,
       CalculateVWithRFC5054TestVectorGroup6_ShouldMatchReference) {
  const unsigned int groupId{6};
  const std::string xHex{_xRFC5054TestVectorValue};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const unsigned int g{_srpParametersMap.at(groupId)._g};
  const std::string vHex{
      MyCryptoLibrary::SecureRemotePassword::calculateV(xHex, NHex, g)};
  const std::string vExpected{
      "61708BC4B7BFD9DDB4AB62BB393240315C971E2BD347EC3EFEAC435F82B27157BC609000"
      "2A27B607C21010BFA471976C7476EFD356F312D68C25F464804E566BFD34C7E9F56FAFF6"
      "9FE3CA094ADE6FE5F5B0AA782569BA4163CA6727B845A920DE2309A4D15310B7EA4A5322"
      "971CA9524676C7B7D2E380A725A8EA6C8B049B2F2F69F5F0E7190A7BA24046290FD08B70"
      "DE4E2E5384F58106C6017FB63BD4DFE867D8D594E37AAFD011B891BDB627CFD90EE88C14"
      "63C63E9587CE4A5461DECCC91C6627B4F9E989FB11A55BCDF4FFA76786650634185C79FD"
      "D7CD04B761FA78D8252325E47B4E4C58CDDB40B58DFF06C4A2070EABC3A85CB518E7F4E6"
      "149F3A08DE96226FF336149AB0C5AF51D10A5FDBC816D094107DD9BAE6E9B997E013DA6F"
      "97F2BDB800FFDB726E3D7266A87C1490B306E10CADC0BE05186526445B5324FC5F5C258C"
      "0572684CC2F44EDC5F8C2D43C84B88037EA7EFBD96850B70E56899C420665E9A15C99D67"
      "471C0082491B233CE05A41DE0843C9F0127007C56E86701A172C97AD3AD84152840B560E"
      "B06B060F56BFCC34C5DC361A6271D9CA165983FC733D454C50EAB45ACEB0EB4DE3C6EBB8"
      "6F2270E5EEDE5DDC2E5082029E8CC6DE29ED28C968574A7AE10DD1506406AFFA1899C1DE"
      "DB8842F2DEBFAD1CEBC5A6258897E09DFB7A6F4127218890786E371C73333ED299D04EE1"
      "10679DBB100A61B590B4806A1A8554A98FB1B5BBA8C6F43BB20BC495FD8249495DA4C8CF"
      "6F5E691BD0C138B33F270BA722AB76D175D18BF42A8261FD3AFE7BE47DAE9743A35F6E38"
      "E442E10DC217D33750CFFFC470E6C9EBD19EC57078A22AA235334176B644C97750A54194"
      "5CF4A0B09CB0D2BAE839172934B68964A86CA56371045DA404BC879647B3B2EFC76C08DE"
      "4237E404F5D197900F1C34A2D4570F7EF4C49DBF623732A97B34320AA82F8B06549177DB"
      "5AD68AC3E6B0A0933EB22426EDD367B9E07107EFC9CA91DC2095B6E4A156D87FF3B5135A"
      "571F3A28BBD8B571BE261696DA6BD81BE7449B276DE444B1FAF2268289C43949C042E801"
      "B2A29D9295A9660B0CA222C3"};
  EXPECT_EQ(vHex, vExpected);
  // Check that v is in the correct range: 1 < v < N
  MessageExtractionFacility::UniqueBIGNUM vBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(vHex)};
  MessageExtractionFacility::UniqueBIGNUM nBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(NHex)};
  EXPECT_GT(BN_cmp(vBn.get(), BN_value_one()), 0);
  EXPECT_LT(BN_cmp(vBn.get(), nBn.get()), 0);
}

/**
 * @test Test the correctness of the calculation of the SRP verifier v = g^x mod
 * N using the RFC-5054 test vector for group 7.
 * @brief Verifies that the verifier v, computed from known x, N, and g values,
 * matches the expected reference value from RFC-5054.
 */
TEST_F(SessionDataTest,
       CalculateVWithRFC5054TestVectorGroup7_ShouldMatchReference) {
  const unsigned int groupId{7};
  const std::string xHex{_xRFC5054TestVectorValue};
  const std::string NHex{_srpParametersMap.at(groupId)._nHex};
  const unsigned int g{_srpParametersMap.at(groupId)._g};
  const std::string vHex{
      MyCryptoLibrary::SecureRemotePassword::calculateV(xHex, NHex, g)};
  const std::string vExpected{
      "F3BB0C1E824D5FACA88D2ABD8498B0F98D0C0662E7C51E5D33C2C5754C1A47748E75FAFD"
      "7888656172DFFD5B4A9AB2674A4EAFBAC89EEE766E49DD91C1081B03B73A44000B7A10BA"
      "320AA523EBB6F7FB78B3517ACA34FD6F950BB47E8E12622AD3AB1E53B54307B479CF0136"
      "EFE852D2B232A91DC0B200B829D2493CCF7986EA594AEEC946EDB9226A83DDD12A3BB389"
      "39598676E2796F5AEC344B98DE05AFF5B4590A479C73EE44DAB49007A791356F547D6543"
      "2B6911C945E68C11122033A29255C72A39AE0402E9A105CAE1622D1C83C838CFFE873D6E"
      "57B6807EF1378B8D6CE06C8887C1755261CABEDE3FD4AACB82EAB63BDF63F729939EEEC4"
      "4E5C619958BE8C32E72D91DE809EAB3B82909BC9F96DFB833256C2B9184CB4D20AD00E36"
      "953EC248682197B3FBDFB8AC3401AC9C1E854E167418218E8DDD4167E537752DE45B2A30"
      "F42B2973B38F92308AC9814E64708807578416E022B22B2FA830881B324151893E061F72"
      "E88A09D45120ECC5911806AE39C41BA0367E7FA07C3F0203CA7B505DCC82F221865AD965"
      "6AD7CA42224A89D4D3146D63C9DA7B892E7F2D8C538F3742235DFEEB52EE80521148E75E"
      "B0E8864C3752CEC8970AF07792FF195E3D05024292FB828BA7AE07CCD6FB31C90947B3F7"
      "4A123C6D6423FE1482807D3388E61AD6CC4A5FA8084E66F18FECF385074780BA0D3370D1"
      "466195E85F5F09E46411CDB5907384FC891192EB36DB5773F87C052453952EE51BFE7160"
      "13EB38FE90939077184A97B7AC21E9C69B0EB8E480E1E6979B775CA8BA01E6170D1A270B"
      "50A2EC59D2585BB5548947FA0A28D3A239D825CD3470A255F710B1EC024BDFA3C043B291"
      "F927944D616441647E13263556571B4E080925BC08ECFFF49C0DE569BBC7C8D9FB9B98DD"
      "2A1B5A504794658FCBD377247B43DD8BAA338B054240359D4EF111E941E69BCECB7A892F"
      "6F9459D7F0B1AD69473E6F809EB24E1A008855BCEEF6DA35A53154C0E9E5C0CC9982E26F"
      "EFC060417AEE7B09B2D95F3D3E1D12AB9FA16FD44A78B9021F48DA585AB4A449C3349789"
      "0A1262B6D3E0FD44E021D18AB25F4D4BC9F84F8FA44D6205BB68F56511C831EF0055F0F7"
      "4ACCA2AFC046F76C7E3F0549D0BF6DCAC71ACCB7D513BF9CEB5E61A641EC3192AE0E3F2C"
      "89194592057020C5D762B28DA8EED2BD76E06B0E5118629AFBE57A341BBE5FA75D91874F"
      "07A9862C36541A22EBAB40FCAC5C1ECFD7574DAD0C862BBE99AD7FA894DC429287305255"
      "73D53A521DF1F9481FC11754E7107C4DCA43B744AA8DEADF28B0CD41456D83BB15887740"
      "AA6F2D711817F4DF4E7CEC0FC97E66CC58A079AE595A419A62173FEC13EC939968EAAA72"
      "3081B14035EDF62F69A3FB3699483AE87C3DE63FDE3C8FB60322024C40E0F43A307BC520"
      "A89027A1A35C490B9F76F078968EEC68"};
  EXPECT_EQ(vHex, vExpected);
  // Check that v is in the correct range: 1 < v < N
  MessageExtractionFacility::UniqueBIGNUM vBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(vHex)};
  MessageExtractionFacility::UniqueBIGNUM nBn{
      MessageExtractionFacility::hexToUniqueBIGNUM(NHex)};
  EXPECT_GT(BN_cmp(vBn.get(), BN_value_one()), 0);
  EXPECT_LT(BN_cmp(vBn.get(), nBn.get()), 0);
}

/**
 * @test Test that calculateV throws an error for empty input parameters.
 * @brief Verifies that calculateV throws std::runtime_error when given empty
 * xHex, NHex, or g.
 */
TEST_F(SessionDataTest, CalculateVWithEmptyInput_ShouldThrowRuntimeError) {
  EXPECT_THROW(MyCryptoLibrary::SecureRemotePassword::calculateV("", "ABCD", 2),
               std::invalid_argument);
  EXPECT_THROW(MyCryptoLibrary::SecureRemotePassword::calculateV("1234", "", 2),
               std::invalid_argument);
  EXPECT_THROW(
      MyCryptoLibrary::SecureRemotePassword::calculateV("1234", "ABCD", 0),
      std::invalid_argument);
}

/**
 * @test Test the correctness of the calculation of v for a small group.
 * @brief Verifies that calculateV works for small values.
 */
TEST_F(SessionDataTest, CalculateVWithSmallValues_ShouldMatchReference) {
  const std::string xHex = "05";
  const std::string NHex = "17"; // 23 in decimal
  const unsigned int g = 2;
  // v = 2^5 mod 23 = 32 mod 23 = 9
  const std::string expectedVHex = "09";
  const std::string vHex =
      MyCryptoLibrary::SecureRemotePassword::calculateV(xHex, NHex, g);
  EXPECT_EQ(vHex, expectedVHex);
}
