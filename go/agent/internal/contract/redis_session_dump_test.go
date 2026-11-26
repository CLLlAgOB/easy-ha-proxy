package contract

import (
	"testing"

	"easy-ha-proxy/panel/shared/pyyaml"
)

// A Redis that cannot read its session dump must not take the sign-in page
// down: Redis 8 reads what 7.4 wrote, but 7.4 refuses what 8 wrote and
// exits, so rolling the image back would leave the gateway with no login
// page. The role checks the dump with redis-check-rdb before recreating the
// stack (the guard itself is tested in apply/stages/redis_guard_test.go);
// this holds the role's wiring and the paths it shares with the compose
// file.

const redisGuardCompose = "ansible/roles/authelia/templates/docker-compose.yml.j2"

func TestRedisGuardChecksTheImageTheComposeFileRuns(t *testing.T) {
	compose := read(t, redisGuardCompose)
	mustContain(t, compose, "image: {{ authelia_redis_image", "docker-compose.yml.j2")
	raw, err := pyyaml.Load([]byte(read(t, "ansible/roles/authelia/defaults/main.yml")))
	if err != nil {
		t.Fatal(err)
	}
	defaults, ok := raw.(*pyyaml.Map)
	if !ok {
		t.Fatal("authelia defaults/main.yml is not a mapping")
	}
	value, ok := defaults.Get("authelia_redis_image")
	if !ok {
		t.Fatal("authelia defaults have no authelia_redis_image")
	}
	image, ok := value.(string)
	if !ok {
		t.Fatalf("authelia_redis_image is %T, want a string", value)
	}
	// The guard must check the very image the compose file defaults to.
	mustContain(t, compose, "default('"+image+"')", "docker-compose.yml.j2")
}

func TestRedisDumpLivesWhereTheComposeFileMountsIt(t *testing.T) {
	mustContain(t, read(t, redisGuardCompose),
		"- {{ authelia_redis_data_dir }}:/data",
		"docker-compose.yml.j2")
}
