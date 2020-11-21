import java

class BuildConstraintViolationWithTemplateSink extends Method {
    BuildConstraintViolationWithTemplateSink() {
        this.getName() = "buildConstraintViolationWithTemplate" 
    }
}

from Method m
where m.overridesOrInstantiates(any(BuildConstraintViolationWithTemplateSink t))
select m , "This is a valid synk" 