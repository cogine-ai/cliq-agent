#include <assert.h>
#include <stdio.h>
#include "dependency-descriptors.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"dependency descriptor check failed at %d\n",__LINE__); return 1; } } while (0)
int main(void) {
 const char *digest="67b21af4070f79e9c2b016bcd785b7ca2c5fd9968270455668eca894326a4ce7";
 const char *one="{\"descriptors\":[{\"canonicalPackagePath\":\"/a/-/a-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"a\",\"packageVersion\":\"1.0.0\"}],\"firstIndex\":0,\"schemaVersion\":1}", *two="{\"descriptors\":[{\"canonicalPackagePath\":\"/b/-/b-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"b\",\"packageVersion\":\"1.0.0\"}],\"firstIndex\":1,\"schemaVersion\":1}", *both="{\"descriptors\":[{\"canonicalPackagePath\":\"/a/-/a-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"a\",\"packageVersion\":\"1.0.0\"},{\"canonicalPackagePath\":\"/b/-/b-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"b\",\"packageVersion\":\"1.0.0\"}],\"firstIndex\":0,\"schemaVersion\":1}";
 struct cliq_dependency_descriptors plan;
 CHECK(cliq_dependency_descriptors_initialize(&plan,2,digest));
 CHECK(!cliq_dependency_descriptors_at(&plan,0));
 CHECK(cliq_dependency_descriptors_page(&plan,(const unsigned char*)one,strlen(one)));
 CHECK(!cliq_dependency_descriptors_seal(&plan));
 CHECK(cliq_dependency_descriptors_page(&plan,(const unsigned char*)two,strlen(two)));
 CHECK(cliq_dependency_descriptors_seal(&plan));
 CHECK(plan.count==2 && plan.page_count==2 && plan.owned_bytes<=CLIQ_DEPENDENCY_DESCRIPTOR_TOTAL_BYTES);
 CHECK(cliq_dependency_string_equal(cliq_dependency_descriptors_at(&plan,0)->name,"a"));
 CHECK(cliq_dependency_string_equal(cliq_dependency_descriptors_at(&plan,1)->name,"b"));
 CHECK(!cliq_dependency_descriptors_at(&plan,2));
 CHECK(!cliq_dependency_descriptors_page(&plan,(const unsigned char*)two,strlen(two)));
 cliq_dependency_descriptors_dispose(&plan);
 CHECK(!plan.first && !plan.owned_bytes && !plan.initialized);
 CHECK(cliq_dependency_descriptors_initialize(&plan,2,digest));
 CHECK(cliq_dependency_descriptors_page(&plan,(const unsigned char*)both,strlen(both)));
 CHECK(cliq_dependency_descriptors_seal(&plan)); cliq_dependency_descriptors_dispose(&plan);
 const char *bad[]={"{\"descriptors\":[{\"canonicalPackagePath\":\"/a/-/a-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"a\",\"packageVersion\":\"1.0.0\"},{\"canonicalPackagePath\":\"/b/-/b-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"b\",\"packageVersion\":\"1.0.0\"}],\"firstIndex\":0,\"schemaVersion\":1,\"unknown\":0}","{\"descriptors\":[{\"canonicalPackagePath\":\"/a/-/a-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"a\"}],\"firstIndex\":0,\"schemaVersion\":1}","{\"descriptors\":[{\"canonicalPackagePath\":\"/a/-/a-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"a\",\"packageVersion\":\"1.0.0\"},{\"canonicalPackagePath\":\"/a/-/a-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"a\",\"packageVersion\":\"1.0.0\"}],\"firstIndex\":0,\"schemaVersion\":1}","{\"descriptors\":[{\"canonicalPackagePath\":\"/b/-/b-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"b\",\"packageVersion\":\"1.0.0\"},{\"canonicalPackagePath\":\"/a/-/a-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"a\",\"packageVersion\":\"1.0.0\"}],\"firstIndex\":0,\"schemaVersion\":1}","{\"descriptors\":[{\"canonicalPackagePath\":\"/a/-/a-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"a\",\"packageVersion\":\"1.0.0\"}],\"firstIndex\":1,\"schemaVersion\":1}","{\"descriptors\":[{\"canonicalPackagePath\":\"/a/-/a-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"\\u0061\",\"packageVersion\":\"1.0.0\"}],\"firstIndex\":0,\"schemaVersion\":1}","{\"descriptors\":[{\"canonicalPackagePath\":\"/a/-/a-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"a\",\"packageVersion\":\"1.0.0\"}],\"firstIndex\": 0,\"schemaVersion\":1}","{\"descriptors\":[{\"canonicalPackagePath\":\"/a/-/a-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=\",\"packageName\":\"a\",\"packageVersion\":\"1.0.0\"}],\"firstIndex\":0,\"schemaVersion\":1}","{\"descriptors\":[{\"canonicalPackagePath\":\"/../a\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"a\",\"packageVersion\":\"1.0.0\"}],\"firstIndex\":0,\"schemaVersion\":1}","{\"descriptors\":[{\"canonicalPackagePath\":\"/a/-/a-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"A\",\"packageVersion\":\"1.0.0\"}],\"firstIndex\":0,\"schemaVersion\":1}","{\"descriptors\":[{\"canonicalPackagePath\":\"/a/-/a-1.0.0.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"a\",\"packageVersion\":\"1.0.0\"}],\"firstIndex\":0,\"schemaVersion\":1,\"schemaVersion\":1}"};
 for(size_t i=0;i<sizeof(bad)/sizeof(*bad);i++) {
  CHECK(cliq_dependency_descriptors_initialize(&plan,2,digest));
  CHECK(!cliq_dependency_descriptors_page(&plan,(const unsigned char*)bad[i],strlen(bad[i])));
  CHECK(plan.failed && !cliq_dependency_descriptors_seal(&plan)); cliq_dependency_descriptors_dispose(&plan);
 }
 CHECK(cliq_dependency_descriptors_initialize(&plan,2,digest));
 CHECK(!cliq_dependency_descriptors_page(&plan,(const unsigned char*)two,strlen(two)));
 cliq_dependency_descriptors_dispose(&plan);
 CHECK(cliq_dependency_descriptors_initialize(&plan,2,"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
 CHECK(cliq_dependency_descriptors_page(&plan,(const unsigned char*)both,strlen(both)));
 CHECK(!cliq_dependency_descriptors_seal(&plan)); cliq_dependency_descriptors_dispose(&plan);
 CHECK(cliq_dependency_descriptors_initialize(&plan,2,digest));
 plan.owned_bytes=CLIQ_DEPENDENCY_DESCRIPTOR_TOTAL_BYTES-1;
 CHECK(!cliq_dependency_descriptors_page(&plan,(const unsigned char*)one,strlen(one)) && plan.failed);
 cliq_dependency_descriptors_dispose(&plan);
 CHECK(!cliq_dependency_descriptors_initialize(&plan,200001,digest));
 CHECK(cliq_dependency_descriptors_initialize(&plan,0,"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
 /* A wrong empty digest remains a refusal, never an implicit graph. */
 CHECK(!cliq_dependency_descriptors_seal(&plan)); cliq_dependency_descriptors_dispose(&plan);
 printf("dependency_descriptor_checks=%u\n",checks); return 0;
}
