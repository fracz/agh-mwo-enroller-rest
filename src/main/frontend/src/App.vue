<template>
  <div id="app">
    <h1>System do zapisów na zajęcia</h1>
    <div v-if="!auth">
      <login-form @login="enter($event)"></login-form>
    </div>
    <div v-show="auth">
      <h2>Witaj {{ auth }}!
        <a @click="logout()" class="float-right  button-outline button">Wyloguj</a>
      </h2>

      <meetings-page :username="auth"></meetings-page>
    </div>
  </div>
</template>

<script>
    import "milligram";
    import LoginForm from "./LoginForm";
    import MeetingsPage from "./meetings/MeetingsPage"
    import Vue from "vue";

    export default {
        components: {LoginForm, MeetingsPage},
        data() {
            return {
                auth: ""
            };
        },
        mounted() {
            if (localStorage.getItem('token')) {
                this.auth = localStorage.getItem('username');
                Vue.http.headers.common.Authorization = 'Bearer ' + token;
            }
        },
        methods: {
            enter(user) {
                this.$http.post('tokens', user).then(response => {
                    if (response.status === 200) {
                        this.auth = user.login;
                        const token = response.body.token;
                        Vue.http.headers.common.Authorization = 'Bearer ' + token;
                        localStorage.setItem('token', token);
                        localStorage.setItem('username', user.login);
                        this.$http.get('participants');
                    }
                });
            },
            logout() {
                localStorage.clear();
                this.auth = '';
            }
        }
    };
</script>

<style>
  #app {
    max-width: 1000px;
    margin: 0 auto;
  }
</style>

