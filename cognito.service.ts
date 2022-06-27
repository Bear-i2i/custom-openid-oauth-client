import { Injectable, ErrorHandler } from '@angular/core';
import { windowWhen, tap, mergeMap } from 'rxjs/operators';
import { Observable, Subscriber } from 'rxjs';
import { HttpClient } from '@angular/common/http';
import { nextTick } from 'process';
import { THIS_EXPR } from '@angular/compiler/src/output/output_ast';
import { TOUCH_BUFFER_MS } from '@angular/cdk/a11y';

@Injectable()
export class CognitoService {
  private observers: Array<Subscriber<string>> = [];
  constructor() { }

  config = window["configuration"];

  public IsAuhtenticated(): boolean {
    let userInformation = window.localStorage.getItem(`${this.config.clientId}_aouth2`);

    if (Boolean(userInformation)) {
      let data = JSON.parse(userInformation);
      if ((Boolean(data.access_token) && Boolean(data.id_token) && Boolean(data.refresh_token)) || Boolean(data.code)) {
        return true;
      } else {
        window.localStorage.removeItem(`${this.config.clientId}_aouth2`);
        window.location.href = this.config.instance + `/login?client_id=${this.config.clientId}&response_type=code&scope=email+openid&redirect_uri=${this.config.redirectUri}`;
      }
    } else {
      if (window.location.hash.indexOf('id_token') > -1 || window.location.search.indexOf('code') > -1) {
        this.saveSession(window.location.hash + window.location.search, this.config.clientId);
        window.location.href = window.location.origin;
      } else {
        window.localStorage.removeItem(`${this.config.clientId}_aouth2`);
        window.location.href = this.config.instance + `/login?client_id=${this.config.clientId}&response_type=code&scope=email+openid+&redirect_uri=${this.config.redirectUri}`;
      }
    }
  }

  public getUserInfo(): Observable<any> {
    return new Observable<any>((observer) => {
      this.getAccessToken().subscribe(result => {
        let data = this.decodeJWToken(this.getTokenObject().id_token);
        observer.next(data);
      });
    });
  }

  public logOut(): void {
    window.localStorage.removeItem(`${this.config.clientId}_aouth2`);
    window.location.href = this.config.instance + `/logout?client_id=${this.config.clientId}&logout_uri=${this.config.redirectUri}`;;
  }


  private decodeJWToken(jwtToken): any {
    if ((typeof jwtToken === 'undefined' || !jwtToken || 0 === jwtToken.length)) {
      return null;
    };

    var idTokenPartsRegex = /^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$/;

    var matches = idTokenPartsRegex.exec(jwtToken);

    if (!matches || matches.length < 4) {
      return null;
    }

    var crackedToken = {
      header: matches[1],
      JWSPayload: matches[2],
      JWSSig: matches[3]
    };

    //return crackedToken;

    if (!crackedToken) {
      return null;
    }

    try {
      var base64IdToken = crackedToken.JWSPayload;
      var base64Decoded = this._base64DecodeStringUrlSafe(base64IdToken);

      if (!base64Decoded) {
        console.log('The returned id_token could not be base64 url safe decoded.');
        return null;
      }

      // ECMA script has JSON built-in support
      return JSON.parse(base64Decoded);
    } catch (err) {
      console.log('The returned id_token could not be decoded', err);
    }

    return null;
  }



  private _base64DecodeStringUrlSafe(base64IdToken): string {
    // html5 should support atob function for decoding
    base64IdToken = base64IdToken.replace(/-/g, '+').replace(/_/g, '/');

    if (window.atob) {
      return decodeURIComponent(escape(window.atob(base64IdToken))); // jshint ignore:line
    }
    else {
      return decodeURIComponent(escape(this._decode(base64IdToken)));
    }
  }

  private _decode(base64IdToken): string {
    var codes = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    base64IdToken = String(base64IdToken).replace(/=+$/, '');

    var length = base64IdToken.length;

    if (length % 4 === 1) {
      throw new Error('The token to be decoded is not correctly encoded.');
    }

    var h1, h2, h3, h4, bits, c1, c2, c3, decoded = '';

    for (var i = 0; i < length; i += 4) {
      //Every 4 base64 encoded character will be converted to 3 byte string, which is 24 bits
      // then 6 bits per base64 encoded character
      h1 = codes.indexOf(base64IdToken.charAt(i));
      h2 = codes.indexOf(base64IdToken.charAt(i + 1));
      h3 = codes.indexOf(base64IdToken.charAt(i + 2));
      h4 = codes.indexOf(base64IdToken.charAt(i + 3));

      // For padding, if last two are '='
      if (i + 2 === length - 1) {
        bits = h1 << 18 | h2 << 12 | h3 << 6;
        c1 = bits >> 16 & 255;
        c2 = bits >> 8 & 255;
        decoded += String.fromCharCode(c1, c2);
        break;
      }
      // if last one is '='
      else if (i + 1 === length - 1) {
        bits = h1 << 18 | h2 << 12
        c1 = bits >> 16 & 255;
        decoded += String.fromCharCode(c1);
        break;
      }

      bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;

      // then convert to 3 byte chars
      c1 = bits >> 16 & 255;
      c2 = bits >> 8 & 255;
      c3 = bits & 255;

      decoded += String.fromCharCode(c1, c2, c3);
    }

    return decoded;
  }

  private requestToken(code): void {
    let self = this;
    var requestInfo = {
      client_id: this.config.clientId,
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: window.location.origin
    };

    const XHR = new XMLHttpRequest();
    let urlEncodedData = "",
      urlEncodedDataPairs = [],
      name;
    for (name in requestInfo) {
      urlEncodedDataPairs.push(encodeURIComponent(name) + '=' + encodeURIComponent(requestInfo[name]));
    }
    urlEncodedData = urlEncodedDataPairs.join('&').replace(/%20/g, '+');
    XHR.onreadystatechange = function (event: any) {
      if (XHR.readyState == XMLHttpRequest.DONE) {   // XMLHttpRequest.DONE == 4
        if (XHR.status == 200) {
          self.saveSession(event.target.responseText, self.config.clientId);
          for (let observer of self.observers) {
            observer.next(JSON.parse(event.target.responseText).access_token);
          }
        }
      }
    };

    XHR.open('POST', this.config.instance + '/oauth2/token');
    XHR.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

    // Finally, send our data.
    XHR.send(urlEncodedData);
  }

  private saveSession(response: string, clientId): void {
    let session = null;
    if (response.startsWith('?')) {
      session = response
        .slice(1)
        .split('&')
        .map(p => p.split('='))
        .reduce((obj, pair) => {
          const [key, value] = pair.map(decodeURIComponent);
          obj[key] = value;
          return obj;
        }, {});
    } else if (response.startsWith('{')) {
      session = JSON.parse(response);
    }
    session.expires = Date.now() / 1000;
    window.localStorage.setItem(`${clientId}_aouth2`, JSON.stringify(session));
  }

  private refreshToken(refreshToken): void {

    let self = this;
    var requestInfo = {
      client_id: this.config.clientId,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    };
    const XHR = new XMLHttpRequest();
    let urlEncodedData = "",
      urlEncodedDataPairs = [],
      name;
    for (name in requestInfo) {
      urlEncodedDataPairs.push(encodeURIComponent(name) + '=' + encodeURIComponent(requestInfo[name]));
    }
    urlEncodedData = urlEncodedDataPairs.join('&').replace(/%20/g, '+');
    XHR.onreadystatechange = function (event: any) {
      if (XHR.readyState == XMLHttpRequest.DONE) {   // XMLHttpRequest.DONE == 4
        if (XHR.status == 200) {

          self.saveSession(event.target.responseText, self.config.clientId);
          for (let observer of self.observers) {
            observer.next(JSON.parse(event.target.responseText).access_token);
          }
        }
      }
    };

    XHR.open('POST', this.config.instance + 'oauth2/token');
    XHR.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

    // Finally, send our data.
    XHR.send(urlEncodedData);
  }

  public getAccessToken(): Observable<string> {
    let data = this.getTokenObject();
    if (Boolean(data.code)) {
      return new Observable<string>((observer) => {
        if (this.observers.length == 0) {
          this.requestToken(data.code);
        }
        this.observers.push(observer);
      });
    }

    if (Boolean(data.access_token) && Boolean(data.refresh_token)) {
      let tokenInfo = this.decodeJWToken(data.access_token);
      let now = Date.now() / 1000;
      if (now >= tokenInfo.exp) {
        //we need to request a token
        return new Observable<string>((observer) => {
          if (this.observers.length == 0) {
            this.refreshToken(data.refresh_token);
          }
          this.observers.push(observer);
        });
      }
    }
    return new Observable<string>((observer) => {
      return observer.next(data.access_token);
    });
  }


  private getTokenObject(): any {
    return JSON.parse(window.localStorage.getItem(`${this.config.clientId}_aouth2`));
  }
}
