<template>
  <div>
    <label>E-mail</label>
    <input type="email" v-model="email">
    <label>Hasło</label>
    <input type="password" v-model="password">
    <button @click="enter()">{{ buttonLabel }}</button>
  </div>
</template>

<script>
    export default {
        props: ["buttonLabel"],
        data() {
            return {
                email: "",
                password: ""
            };
        },
        methods: {
            enter() {
                this.$emit("login", {login: this.email, password: this.password});
            }
        },
        mounted() {
            if (!this.buttonLabel) {
                this.buttonLabel = "Zaloguj się";
            }
        }
    };
</script>
