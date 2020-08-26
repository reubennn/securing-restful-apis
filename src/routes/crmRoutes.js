import {
    addNewContact,
    getContacts,
    getContactWithID,
    updateContact,
    deleteContact
} from '../controllers/crmController';
import { login, register, loginRequired } from "../controllers/userControllers"

const routes = (app) => {
    app.route('/contacts')
        .get((req, res, next) => {
            // middleware
            console.log(`Request from: ${req.originalUrl}`)
            console.log(`Request type: ${req.method}`)
            next();
        }, loginRequired, getContacts) // first runs loginRequired, then getContacts

        // POST endpoint
        .post(loginRequired, addNewContact);

    app.route('/contact/:contactId')
        // get specific contact
        .get(loginRequired, getContactWithID)

        // put request
        .put(loginRequired, updateContact)

        // delete request
        .delete(loginRequired, deleteContact);

    // Registration route
    app.route("/auth/register")
        .post(register);

    // Login route
    app.route("/login")
        .post(login);
}

export default routes;
