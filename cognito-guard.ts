import { Injectable } from '@angular/core';
import { CanActivate } from '@angular/router';
import { CognitoService } from '../services/cognito/cognito.service';

@Injectable()
export class CognitoGuard implements CanActivate {

  constructor(private authService: CognitoService) { }

  canActivate() {
    return this.authService.IsAuhtenticated();
  }
}
